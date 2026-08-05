# Multi-Device Contacts — Implementation Plan (R1)

**Status:** Ready to scope into R0 gates. No code written yet.
**Date:** 2026-08-03, revised same day (mothership authority model)
**Supersedes nothing** — this compiles [ROADMAP.md](ROADMAP.md) R1 and [FINDINGS.md](FINDINGS.md) into an ordered, gated task list. Read those two first; this doc doesn't repeat their reasoning, only their conclusions.

---

## Where this came from

A HYPR competitive review (2026-08-03) suggested Occulta add a self-service "trusted devices" list with per-device revocation, on the reasoning that it needs no server. On checking prior work, that's the same ambition Design Session 5 already evaluated and **shelved** on 2026-07-10: the only cheap way to make a device list *useful* — a contact accepting a new device on another device's signature — is the cert-vouching mechanism Design Session 3/4 rejected outright, because a single coerced pairing ceremony would silently compromise a victim's whole contact graph with no physical tell. That's exactly the attack class the duress cluster exists to close. **No device-list/picker UI is in scope. This isn't a new decision — it's re-confirming an existing one before scope creeps back in.**

What survives, and is genuinely unbuilt, is narrower than "device management": a data-model bug fix, plus a revocation broadcast that was fully designed on 2026-07-05 but — confirmed by grep, 2026-07-10 — has zero code behind it.

---

## Scope of this plan

1. **The overwrite bug.** Pairing a second device with an existing contact silently overwrites the first device's key. Real defect, independent of everything else below.
2. **The revocation broadcast, authority restricted to the mothership.** `occulta-device-revocation-v1` — the contact's current mothership device (Q-07's "trusted device," now also governing revocation per Design Session 7) signs and sends a direct revocation to every contact who has the lost device's key pinned; a signature from any other device is rejected. Fully designed (FINDINGS.md Design Sessions 3 & 7, ROADMAP.md R1 §6). **Not implemented anywhere in the codebase.** This is the actual "revoke a compromised device" capability — it ships as a signed broadcast + a contact-side authority check, not a UI screen.
3. **The blocking prerequisite.** Q-07: Vault/shard custody has no device provenance. Shipping (1) or (2) into a codebase where a second device can reach `ShardCustodyManager` risks false-loss flags or incorrect shard handback — a correctness-and-safety bug in the system that exists specifically to prevent data loss. This must close first.

## Explicit non-goals (carried forward, not re-litigated)

- No device list / picker / dashboard UI (Q-05, resolved no)
- No cert-vouching or any mechanism that grants trust without a fresh physical UWB exchange (Design Session 3–4, standing principle `no-self-vouching-device-trust`)
- No mesh/gossip revocation propagation (Design Session 3, rejected — leaks graph structure, marginal speed gain)
- No promoted "add a device" flow, checklists, or reminders (Design Session 5, Alert #7 — accepted friction, not mitigated)

---

## Sequencing

```
R0 design gates (checklist, domain prefixes, threat-model delta — ROADMAP.md §R0)
        │
        ▼
Q-07 fix: Vault custody "trusted device" resolution   ◄── BLOCKING, must land first
        │
        ▼
D-01–D-06: concurrent device-key data model            ── can start once Q-07 lands
        │
        ▼
R1 §6: revocation broadcast (occulta-device-revocation-v1)
        │
        ▼
Q-06: split reset(identity:) into per-device revoke vs. forget-contact
        │
        ▼
§9 test suite + CI fixtures
```

Data model and revocation broadcast are sequenced serially here for review bandwidth, not because of a hard dependency — the broadcast's payload (`lostDevicePubKey`) needs `deviceID` to exist on `Key` first, so in practice D-01–D-06 does come first regardless.

---

## Step 1 — R0 design gates (one sprint, zero code)

Per ROADMAP.md §R0, narrowed to what R1 actually needs (R2–R3 gates are separate, not part of this plan):

- [ ] Run `CRYPTO_REVIEW_CHECKLIST.md` against the concurrent-key data model and per-device prekey scoping (no new protocol — the exchange ceremony is unchanged)
- [ ] Register domain prefix `occulta-device-revocation-v1` in the `SaltInfo`/constants pattern
- [ ] Write the threat-model delta doc per the revised ROADMAP.md §R0.3 (2026-08-03): pairing itself still has no delta, but the mothership/revocation/custody-authority design now does — mothership is not a single global property of an identity (can differ per contact), revocation is eventually-consistent not guaranteed-delivered, and the duress-resistance benefit isn't automatic without deliberate (currently unsupported) device placement. State all four explicitly, not just the pairing-mechanism line.
- [ ] Confirm wire-format rule: everything rides as optional sub-envelopes on `SealedPayload` (`v3fs` + existing modes). No new `Version`/`Mode` case.

## Step 2 — Close Q-07 (blocking)

Fix direction revised 2026-08-03 (FINDINGS.md Design Session 8 — supersedes the sender-gating half of Design Session 6's "v2"), not implemented, not fully verified:

- [ ] Implement "trusted device"/mothership resolution: oldest key with `expiredOn == nil` per contact (`Key.acquiredAt`), computed independently on both sides, zero new wire messages
- [ ] Send `shardOperations`/`custodyManifest`/`expectedShards` **uniformly to every active device of a contact** — no per-recipient branching in the payload-assembly pass (Design Session 8: sender-side gating dropped, in both directions — outbound custody instructions are not withheld from non-mothership devices either)
- [ ] **Receiver-side authority check in `processInboundManifest`/`processExpectedShards` is the sole enforcement mechanism, not a backstop:** verify sender fingerprint matches the independently-resolved mothership; discard everything else unconditionally (mirrors the existing `isFallback` filtering posture — don't trust the sender to have gated correctly)
- [ ] Add local gate: a newly-paired second device does not get Vault-initiating capability by default
- [ ] Verify `mismatchHandbackOps`'s actual implementation before relying on its documented behavior (only the doc comment has been read so far, per FINDINGS.md)

**Gate:** do not proceed to Step 3 until this is implemented and its own tests pass (tamper cases, trusted-device recomputation on revocation, no false-loss flagging from a second device's empty manifest, uniform-send-then-discard behavior verified for at least one non-mothership device).

Trustee resync (the newly-promoted mothership rebuilding custody state after Step 4's promotion) is scoped separately in Step 4 — it depends on this step's authority check but isn't triggered until a promotion actually happens.

## Step 3 — D-01–D-06: concurrent device-key data model

- [ ] Add `deviceID: String?` to `Contact.Profile.Key` (Q-04, Option A — confirmed, not a new `Device` entity). Lightweight SwiftData migration; existing rows get `deviceID == nil`, treated as one implicit legacy device, no backfill.
- [ ] Mint `deviceID` once, at first exchange with that specific device (D-03) — never derived from device name/OS/anything observable
- [ ] Split all 34 `contactPublicKeys` call sites (D-06) into fan-out (`.filter { $0.expiredOn == nil }`, all active devices) vs. display (keep `.last`-style single-key selection — cosmetic, no UI change needed per Q-05)
- [ ] Extend SE prekey tag to `"prekey.<contactID>.<deviceID>.<id>"`; confirm `seTagPrefix(contactID:)` still prefix-matches correctly (D-02)
- [ ] `ContactManager` fans out one `GroupRecipient` per (contact, device) pair, each with that device's own `pendingBatch` against that device's own replenishment threshold (D-04) — reuses the existing group-messaging envelope unchanged (D-01), no wire format change
- [ ] Write the trace test proving device A never consumes or ships device B's prekeys — flagged in ROADMAP.md as "the one place this plan can recreate the documented historical prekey flaw"
- [ ] "Add a device" entry point on `Contact.Profile`: user-triggered, runs the ordinary UWB exchange, attaches result as a new device slot on the existing profile instead of creating a new contact (D-07) — no auto-detection, no cert

## Step 4 — R1 §6: revocation broadcast, authority restricted to mothership

Currently zero code. Building it for real. Authority model added 2026-08-03 (FINDINGS.md Design Session 7) — revocation is no longer symmetric across an identity's own devices:

- [ ] Mothership device (Q-07's "trusted device": oldest key with `expiredOn == nil` for that contact — same computed value, now also governing this) SE-signs `occulta-device-revocation-v1 ∥ lostDevicePubKey ∥ timestamp` when the *lost* device is a secondary
- [ ] Broadcast directly to every contact who has the lost device's key pinned (no relay/gossip — Design Session 3 resolution)
- [ ] Contact-side: **before dropping the key, verify the signer is that identity's currently-recomputed mothership** — not just any previously-pinned device key. A signature from a non-mothership device must be rejected, not merely deprioritized (this is the actual fix for the symmetric-revocation gap Design Session 7 found — get the receiver-side check wrong and the restriction is cosmetic)
- [ ] Tamper table: flipped fields → signature fail; signature from a valid-but-non-mothership device → rejected
- [ ] Replay idempotence: a revocation seen twice is a no-op
- [ ] **Voluntary handoff path (Design Session 9):** mothership signs a revocation of its own public key to hand authority to the next-oldest device — same signing/broadcast code as revoking a secondary, just targeting self. No guardians involved; this must not be accidentally routed through R2.
- [ ] If the *lost* device is the mothership itself and unavailable to sign anything: no code path here handles it — routes to R2's guardian cert release (ROADMAP.md R2 §4, revised framing). After R2 completes, mothership status shifts to the next-oldest surviving device automatically, no separate promotion step or broadcast needed
- [ ] **[HIGH, required before ship — Design Session 9, mechanism resolved in Design Session 10] Unconditional reattachment, no ack:** every outbound bundle to a contact carries the full known-revoked-device set for that identity, unconditionally, for as long as the relationship exists. No acknowledgment tracking — redundant delivery is safe because revocation processing is already idempotent. Test: contact offline during the original broadcast, comes back online later via any ordinary send, eventually converges without any explicit ack round-trip.
- [ ] **UI: "contacts who may not know yet" list.** Informational only, decoupled from the reattachment mechanism above (which runs regardless). Driven by an honest proxy signal — last bundle-exchange timestamp with that contact vs. when the revocation was issued — not true confirmation, since none is obtainable without an ack. Surfaces the residual, permanently-unclosable case (a contact never messaged again) instead of leaving it silent.

### Step 4a — Trustee resync after promotion (Design Session 8)

The newly-promoted mothership has zero local custody history (secondaries never get Vault-initiating capability, per Step 2) — this rebuilds it. Depends on Step 2's authority check.

- [ ] Newly-promoted device requests custody state from each known trustee
- [ ] Trustee verifies the requester resolves as *its own* independently-computed mothership for that identity (Step 2's mechanism, reused — no new primitive) before answering
- [ ] **Open, not resolved:** does this request fire automatically the instant promotion completes, or does it need its own user confirmation? (Design Session 6/8)
- [ ] **Race condition test, newly identified (Design Session 8):** a trustee who hasn't yet processed the revocation broadcast still resolves the *old* device as mothership and will reject a legitimate resync request. Define retry/backoff behavior explicitly — this must not fail silently or surface as a permanent error
- [ ] Verify `Vault+Manager+Reconstruction.swift`'s actual resync capabilities before scoping this further (still unverified as of Design Session 6)

## Step 5 — Q-06: split `reset(identity:)`

- [ ] Current behavior (`contact.contactPublicKeys?.last?.expiredOn = ...`) only expires the most-recently-added key — under multi-device this silently leaves every other device's key live while looking like a full reset
- [ ] Split into two explicit operations: revoke one device's key (triggers Step 4's broadcast) vs. forget the entire contact (all devices)

## Step 6 — Tests + CI gate (ROADMAP.md §9)

- [ ] Data-model migration test (legacy rows → `deviceID == nil`, treated as one device)
- [ ] Fan-out correctness at all 34 call sites
- [ ] Prekey/pool isolation trace test (Step 3)
- [ ] Revocation: tamper table, replay idempotence, mothership-loss fallthrough to R2, and — the critical regression test for Design Session 7 — a signed revocation from a valid non-mothership device is rejected, not honored (Step 4)
- [ ] Custody transport: a manifest/expectedShards payload from a valid-but-non-mothership device is discarded, not partially trusted (Step 2, Design Session 8 — this is the test that proves the enforcement point actually holds now that sender-side gating is gone)
- [ ] Trustee resync: successful rebuild after promotion, plus the not-yet-processed-revocation race case (Step 4a)
- [ ] Mandatory old/new build fixture: a pre-multi-device build decodes a multi-key-carrying bundle and renders the message untouched, unchanged wire format
- [ ] Fixtures committed to CI permanently

---

## Open items requiring sign-off before Step 2 starts

- `Vault+Manager+Reconstruction.swift`'s actual resync capabilities — unverified, referenced but not read in FINDINGS.md
- `mismatchHandbackOps`'s real implementation vs. its doc comment
- Whether trustee resync after "my other device is gone" is automatic or needs its own user confirmation (Design Session 6, explicitly left open)

---

## References

- [ROADMAP.md](ROADMAP.md) — R1 full spec, R0 gates, cross-release exit criteria
- [FINDINGS.md](FINDINGS.md) — D-01–D-08, Q-01–Q-07, Design Sessions 1–6 (all reasoning behind the decisions this plan executes)
- [CRYPTO_REVIEW_CHECKLIST.md](../../Audit/CRYPTO_REVIEW_CHECKLIST.md) — Step 1 gate

# Recovery-Buffer-Gated Storage — Shard Buffer and Restore State

**Status:** design, not built. **Owner entries:** `Docs/Features/Secure Mode/bugs.md` Bug 102 (BEK,
shared with the sibling doc), Bugs 93, 95, 96, 99, 100, 101 (this container's own). **Compiled:**
2026-09-02, split out of `STORAGE_LAYERING.md` alongside
[`VAULT_KEY_LAYERING.md`](VAULT_KEY_LAYERING.md) once the container boundary turned out to be the real
seam — see that doc's §7 for exactly where the two touch (one join point: completion) and don't.

**What this is.** Everything sealed under the recovery buffer / shard custody key: shards collected
during an active restore, per-depth arming and restore state, and (candidate) `CustodyShard`. This
doc assumes the "why storage needs layering at all," the `LayerStore` mechanism, and the three
protection domains from the sibling doc's §1–§4 — read those first if this container's reasoning
doesn't stand on its own. The short version: this container's key (`deriveRecoveryBufferKey()`) is
deliberately **not** biometric-gated, because shards arrive over ordinary messaging, asynchronously,
and gating receipt behind a Face ID prompt would be a real UX regression — that's the whole reason this
is a second container and not a field in the vault-key-gated one.

---

## 1. What is and is not layered today

| Thing | Scope | Consequence |
|---|---|---|
| Pending `.occbak` | one file, device-wide | a restore armed in one layer blocks every other layer from arming |
| Restore shard buffer | `ReconstructShard` rows, no depth | shards cannot be attributed to a layer before reconstruction |
| Completion | depth 0 only | completes in one layer and not the other — a coercer-triggerable test |

Restored vault *entries* land correctly per-depth already (`importBackup` stamps `visibleThroughDepth`
on the way in) — it's the machinery *around* that import, not the import itself, that's device-wide.

---

## 2. Shard attribution — the mechanism that makes per-layer work

An arriving shard carries `entryID = distributionID` for a BEK the device does not have yet. Nothing
in the shard says which layer's restore it belongs to. Filing it into the current depth's slot misfiles
a real trustee's delivery made while the user is at a duress depth; broadcasting it into every slot
makes a coercer's restore advance faster than his own deliveries explain, which tells him another layer
exists.

**Resolution: gate inbound processing on sender visibility at the current depth.** Contacts already
partition by layer — one paired at depth 2 has `originDepth = 2` and is hidden at 0; a sensitive
trustee has `visibleThroughDepth = 0` and is visible only there. So a shard arriving at depth N
provably came from a contact that exists at depth N, and belongs to depth N's restore. Attribution
solves itself, and per-depth buffers become correct rather than dangerous.

**Dropping a mis-depthed shard is safe, and only because handback retries.**
`ShardCustodyManager.mismatchHandbackOps` puts handback ops on *every* outbound bundle to the owner
until they redistribute — so a shard refused during a duress session returns on the trustee's next
bundle. Without that property this design would trade a starvation channel for data loss.

**This gate does not exist today.** `identifyOwner` resolves senders through `fetchAllContacts()`,
which predicates on `deletionToken` alone. Adding it is the load-bearing piece of this container's
design, and it has scope beyond shards — see §7.

---

## 3. Caps, and why they are only safe here

Fixed width implies a cap on shards per depth. That closes Bug 96 item 2's unbounded growth for free.

**A cap on a *shared* buffer would be a cross-layer denial channel** — an attacker fills it with junk
and evicts a real recovery's shards. The cap is safe only once the buffer is per-depth. Do not add one
before then — see §6's anti-pairings.

---

## 4. Build stages

| # | Stage | Verify |
|---|---|---|
| 3 | Sender-visibility gate on inbound processing (§2), with the drop/defer decision from §7 | a shard from a contact hidden at the current depth is not banked; a trustee's retry lands when the user returns to their depth |
| 4 | Per-depth restore state: arming, sealed backup contents, shard buffer, per-depth cancel | arming in duress does not block depth 0; cancel clears only its own layer |
| 6 | Restore the truthful acknowledgment — each layer answers about its own slot | at every depth the reply is that layer's truth and matches what a real session there produces |

Stage 5 (completion) lives in `VAULT_KEY_LAYERING.md` §7 — it's the one step that reads this
container's collected shares and writes the reconstructed BEK into the other one's slot.

---

## 5. Where it lives

A `LayerStore`-shaped sibling file, sealed under the recovery buffer key — not `AppLayerConfig`, for
the same reason as the vault-key-gated container: that row is read on every security check and
SwiftData loads the whole row, so bulk payloads shouldn't ride along. Eagerly created from first
launch, same reasoning as the sibling doc's §3.

Likely holds the larger payloads of the two containers — shard buffers and a pending backup snapshot
are more variable-sized than the vault-key-gated container's BEK record and short-text vault entries —
so the `AppLayerConfig`-exclusion argument applies more forcefully here.

---

## 6. Open decisions

5. **Slot size cap for the backup contents / pending-restore snapshot.** Fixed slots cap vault backup
   size. Pick the cap and enforce it at **export**, with a clear failure — not at restore, when the
   user has no vault left.

6. **Drop versus defer for non-shard payloads** behind §2's gate. Shards retry (§2); messages do not.
   Deferring means storing the bundle, which is a cross-layer container again unless it too is slotted.

7. **Whether `CustodyShard` folds into this container.** Same key domain as the shard buffer, so
   likely the same file once decided — `LayerStore.md` already records its duress-mode accessibility
   as a deferred question, and §2's gate needs the same answer for it that it needs for BEK shards.

8. **The `storePendingRestore` tombstone soft spot.** A downgraded build can still *arm* a restore
   against the sibling doc's tombstoned legacy row, because that one site uses `try?` where its
   siblings use `try` — `alreadyHasBEK` reads false against filler. Arming is this container's action,
   even though the check reads the other container's row. Accept it, or add a guard distinguishing
   "no row" from "row present, undecryptable."

**Anti-pairings:**
- **Do not cap the restore shard buffer before the buffer is per-depth.** §3. Most likely to be picked
  up as obvious housekeeping by someone who hasn't read the reasoning — it introduces a cross-layer
  denial channel.
- **Do not pad the `.occbak` (Bug 100 r3) before item 5 above is decided.** If backup contents move
  into slots, that file stops existing.
- **Do not ship Bug 100 r1 alone.** It excludes the measurement while Bug 101 leaves the content
  unsealed in `Documents/Inbox`. One device session verifies both.

**Known scope creep.** §2's gate applies to inbound processing generally, not just shards. Shards are
the only payload with a retry guarantee, so messages and prekeys need their own answer (item 6 above).
Expect Stage 3 to grow — don't let this get absorbed silently into it.

---

## 7. Bugs — this container's

| Bug | What | Status |
|---|---|---|
| 93 | Vault recovery was depth-blind in state, UI and trigger | fixed; its harm-4 follow-up is partly reverted by this design |
| 94 | Restore path trusted attacker-supplied material | all three remedies in — overwrite refusal, trustee attestation, confirmation |
| 94a | Remedy 2's attestation field unpadded — slot size named the trustee mid-recovery | fixed — every op ships an attestation, real or filler |
| 95 | One poisoned shard permanently blocks legitimate recovery | open — Bug 94 remedy 2 narrows the attacker population but doesn't close it; still no subset search, no discard-restore UI |
| 96 (item 1) | Two traps on decoded content | fixed |
| 96 (item 2) | Restore shard buffer unbounded | open — cap falls out of §3 |
| 96 (item 3) | Export plaintext left unzeroed | open |
| 99 | A coercer supplying his own trustees can test for duress | open — subsumed here except the pending-file tag |
| 100 r1 | Restore artifacts not excluded from device backups | fixed 2026-08-27 |
| 100 r2 | Shard file length was a keyless progress counter | fixed — rows; superseded by this design's slots |
| 100 r3 | `.occbak` length estimates vault size | open — moot once §5 slots the contents |
| 101 | `Documents/Inbox` copies retained and backed up | open — needs a device check |

See [`VAULT_KEY_LAYERING.md`](VAULT_KEY_LAYERING.md) §6, §8 for Bugs 92, 102, 105 — this container's
sibling issues, not its own.

**Adjacent, not this design's subject, same root cause:** Bugs 103/104 (inbound views render a hidden
contact's identity) — closed as duplicates of an accepted limitation, but instances of "the depth
dimension was not applied at the view layer," and §2's gate is the server-side half of that problem.

---

## 8. Migration — in-flight restores

A restore can sit armed for days while trustees deliver shards in person. Losing that on update is a
real harm. **The destination is unambiguous** — a legacy in-flight restore is depth-0-destined by
construction, so it's adopted into slot 0 and finished by the new mechanism rather than kept alive on
the old path:

| Legacy state | Adopted as | Note |
|---|---|---|
| pending `.occbak` | slot 0's sealed backup contents | straight lift |
| `ReconstructShard` rows | slot 0's shard buffer | needs re-sealing — `deriveRecoveryBufferKey()` isn't depth-derived today while this design requires depth in the HKDF info |
| completion at depth 0 | completion at slot 0 | same behavior, one path (see the sibling doc's §7 Stage 5) |

The re-seal needs the vault unlocked, so adoption runs at the **first depth-0 unlock after update**,
not at launch. Banked shards are adopted as-is, not re-validated against §2's gate — they predate the
gate but were already depth-0-destined and already passed Bug 94 remedy 2's attestation when banked.
If adoption can't complete cleanly, refuse and ask the user to re-arm — a visible, identical-at-every-
depth cost, never a silent fallback to the old rules.

**Rejected: dual-run** (legacy restores finish under legacy rules) — attacker-pinnable: a coercer who
arms before updating keeps every pre-design weakness, including this container's uncapped buffer.
**Rejected: complete-then-migrate** — strictly worse, gated on an event a coercer can indefinitely
prevent by keeping a restore armed (Bug 99).

---

## Regressions this design must not introduce

Shared with the sibling doc, restated here since both containers must hold to them:

- **Slot count must never vary.** N occupied slots readable as N layers, by count or length,
  reintroduces the leak the padding exists to close.
- **Nothing may be created lazily.** An artifact that appears when a feature is first used is a tell
  regardless of how well its contents are sealed.
- **Deferral must not be silently dropped.** Until Stage 5 lands, `attemptBEKRestore`'s depth guard is
  the only thing preventing a duress session from completing a depth-0-armed restore. The guard changes
  shape rather than disappearing.
- **No new depth-conditional UI.** Every prompt, banner and acknowledgment must read identically across
  layers unless the underlying state is genuinely per-layer. Two fixes here were themselves found to be
  new oracles — a confirmation shown only at depth 0, a banner absent above it.

---

## See also

[`VAULT_KEY_LAYERING.md`](VAULT_KEY_LAYERING.md) — the BEK record and vault entries. Independent of
this document except at its §7 Stage 5 (completion, reads this container) and this doc's §6 item 8
(the `storePendingRestore` soft spot, reads the sibling container's tombstoned row).

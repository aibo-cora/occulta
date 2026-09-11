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

**Stage 4 found to be a hard dependency, not just adjacent, 2026-09-08 — see `VAULT_KEY_LAYERING.md`
§8 item 9.** Working out that document's own Stage 2, `reconstructBEK` turned out to need
depth-routing (completing in whichever depth's own trustees supplied the shares, not pinned to depth
0 — the acceptance criterion in that doc's §7 already requires this: a coercer completing a restore
"in his layer" is supposed to work, not fail identically forever, which is its own oracle). That
depth-routed completion has nothing to read from until this container's arming/shard-buffer state is
actually per-depth instead of the single, device-wide file it is today
(`backup-import-cache.occbak`, `refreshPendingRestoreState`/`storePendingRestore`). So Stage 4 here
isn't just "the sibling half of the same feature" — it's a precondition for finishing
`reconstructBEK` correctly over there.

**Testing and migration requirement, every stage — settled 2026-09-07, same rule as the sibling doc.**
A stage isn't done once it builds. It's done once (a) tests cover the behavior in its `Verify` column,
and (b) if the stage touches existing on-device data (§8's in-flight-restore adoption, any future
resize cascading from `VAULT_KEY_LAYERING.md` item 2), there's an explicit migration plan checked for
data loss, not just assumed safe by the design reasoning above. This data has no other copy if a
migration goes wrong.

---

## 5. Where it lives

**Joins the shared pool, not a dedicated sibling file — adopting `VAULT_KEY_LAYERING.md` §8 item 5's
decision, settled 2026-09-06.** That item settled one shared, undifferentiated pool for every internal
concealment container: same directory, filename a fresh random ID on every write, same fixed size
across every file in the pool, disambiguated purely by which of the app's own keys successfully opens
a given file (`AES.GCM.open`'s own authentication failure standing in for a magic byte) — not by
directory name, filename, or size. This container is one of those pool files, opened by the
recovery-buffer key, alongside the vault-key-gated container (vault key) and the migrated contact blob
(Secure-Mode key).

Sealed under the recovery buffer key, still excluded from `AppLayerConfig` for the same reason as the
vault-key-gated container: that row is read on every security check and SwiftData loads the whole row,
so bulk payloads shouldn't ride along. Eagerly created from first launch, same reasoning as the sibling
doc's §3. The exclusion argument is unchanged; what moves is where the excluded payload lives — the
shared pool instead of its own directory.

Likely holds the larger payloads of the two containers — shard buffers and a pending backup snapshot
are more variable-sized than the vault-key-gated container's BEK record and short-text vault entries —
so the `AppLayerConfig`-exclusion argument applies more forcefully here.

**Same-size requirement — resolved 2026-09-07 now that item 2's entry-count mechanism is settled.**
Every pool file must match exactly. At the shared 32-entry starting point, this container's total per
depth (56,065 bytes, item 7) exceeds `VAULT_KEY_LAYERING.md`'s (44,393 bytes, item 2) by a constant
11,672 bytes — constant at every future entry count too, since both containers scale by the same
per-entry term. This container is therefore always the shared-pool floor: `VAULT_KEY_LAYERING.md`'s
container and the migrated contact blob pad up to match this one's size, not the reverse, at every
growth step.

**This whole section needs re-deciding before it's built, flagged 2026-09-11 — cross-referenced from
`VAULT_KEY_LAYERING.md` item 5's own correction, same date.** Everything above is written against
"alongside the vault-key-gated container... and the migrated contact blob" — neither exists as a file
any more. The contact blob was deleted whole (Removal Stage 2); `VaultManager.Backup.LayerStore` (the
vault-key-gated container this section keeps citing, including in its own size-parity arithmetic
against 44,393 bytes) was itself deleted this session, replaced by `BackupEncryptionKey` SwiftData
rows. There is currently no file on the vault-key side to be a sibling to, or to pad up to match, or
to fall below as the "shared-pool floor." `backup-export-meta.dat` is the one real, live internal
file left in that whole domain, and it was never brought into this membership question on either
side — see `VAULT_KEY_LAYERING.md` item 5 for the fuller accounting. Whoever next builds this
container needs to re-decide "where it lives" against whatever actually exists at that point, not
this section's still-unrevised premise; the size-parity numbers above are computed against containers
that no longer exist and cannot be trusted as-is even if the shared-pool decision itself still holds.

---

## 6. Open decisions

5. **Slot size cap for the backup contents / pending-restore snapshot — worked out 2026-09-06, entry-
   count dependency settled 2026-09-07.**

   **Backup contents reuse `VAULT_KEY_LAYERING.md` item 2's numbers, not a separate cap.** A
   pending-restore snapshot for one depth *is* every entry visible at that depth — the same set item
   2's vault-entries field already describes, no narrower "sensitive" subset exists to exclude (see
   that doc's correction on this point). No reason for a portable snapshot to need different capacity
   than the live container producing it: same per-entry shape (1,051 bytes: 16 `id` + 8 `createdAt` +
   1 type tag + 2 length prefix + 1024 content), same 32-entry count.

   **Shard buffer, sized the same way item 3 sized the BEK record.** At most as many incoming shares
   as could ever have been distributed — the Shamir ceiling (255), not the 10-trustee write policy,
   for the identical reason: a legacy restore could be reconstructing a pre-cap distribution.
   `255 × 33 bytes` (1-byte x-coordinate + 32-byte share value) = **8,415 bytes**.

   **Arming/state:** small — timestamp, state enum. Generously, ~64 bytes.

   **Total, this container, per depth: `33,632 + 8,415 + 64 = 42,111 bytes`** — close to but not equal
   to `VAULT_KEY_LAYERING.md`'s 44,393 (item 2 there). Item 5 (file-identity, that doc) requires
   *equal*, not close; resolved below now that item 2's entry-count mechanism is settled — this
   container's own item 7 (adding CustodyShard) is what actually finalizes the number.

   **Confirmed 2026-09-06: multiple depths distributing independently, each to its own trustees,
   doesn't change any of this.** The container's whole shape has been "one slot per depth" since §5.1
   — every depth already gets a fully independent slot, sharing nothing with any other. Depth 2's
   8,415-byte shard buffer holds only depth 2's own incoming shares, from depth 2's own trustees;
   depth 5's is a wholly separate allocation. The total file size (`42,111 × 32 ≈ 1.32 MB`) already
   *is* 32 independent copies of this — multiple depths each running their own distribution and
   restore, simultaneously if it comes to that, is the case this structure was built for, not an
   addition to it. §2's attribution gate (by sender visibility at the depth a bundle arrives at)
   already prevents a shared trustee's shares for one depth landing in another depth's buffer.

   **Settled 2026-09-07, resolving the entry-count question this item's sizing depends on:**
   `VAULT_KEY_LAYERING.md` item 2 chose dynamic expansion by 32 (option B) over a hard ceiling, after
   checking that today's shipped code enforces no vault-entry limit at all — a hard ceiling risked
   truncating real, already-existing user data, the one outcome this design treats as unacceptable
   everywhere else. This container's backup-contents sizing reuses that same mechanism and starting
   count (32), so it grows in lockstep with the sibling container rather than needing its own answer.

   **Confirmed cost: every growth event cascades to all three shared-pool files, not just the vault-key
   container.** A resize there rewrites all 32 depth slots of *that* container, and per item 5 (file-
   identity, that doc) this container and the migrated contact blob must resize to match — not a
   one-time cost, one that recurs whenever real usage crosses a threshold. Accepted as the tradeoff for
   never needing to guess a ceiling that could be wrong.

6. **Drop versus defer for non-shard payloads behind §2's gate — settled 2026-09-06, no deferred
   storage needed for either category.**

   **Messages: excluded from the gate entirely — neither drop nor defer.** This isn't new ground.
   Bugs 103 and 104 (an inbound message from a contact hidden at the current depth rendering that
   contact's identity) were both closed as duplicates of an already-accepted limitation
   (`Non-Safe-Sender-Rejection-Is-A-Duress-Detection-Oracle`): rejecting a message because its sender
   isn't visible at the current depth is itself a detectable signal. Applying §2's gate to message
   content would reproduce exactly that. §2's gate operates on the shard-*operation* portion of an
   inbound bundle only; a bundle can carry a message and a shard-return together, and the gate touches
   the latter without needing to touch the former.

   **Prekeys: drop, safely — self-healing by regeneration, not an explicit retry guarantee.** A
   dropped prekey batch is not lost the way a one-shot secret would be — batches are generated fresh on
   every receive from a contact, so a drop just costs one skipped refresh cycle, corrected automatically
   the next time that contact's traffic arrives. Worst case is more frequent fallback to the
   non-forward-secret path in the interim, not permanent loss.

   **Verified against a real oracle concern, not assumed safe.** Checked whether dropping shards or
   prekeys creates a depth-conditional signal a coercer could detect, given this app's standing
   principle that silence must be indistinguishable from an ordinary session:
   - **No signal on the observing side.** A sender hidden at the current depth was never eligible to
     appear in that depth's own shard-health UI (`bekSetupState`, "waiting for confirmation from X") —
     the trustee picker already filters candidates by `isVisible(atDepth:)`, so a hidden sender's
     shard was never going to show as "expected but missing." There's no gap for a coercer to notice.
   - **No signal on the sending side**, even for the strongest version of this attack (coercer holds
     the victim's phone *and* controls a sending identity): bundle delivery is acknowledged at the
     transport level regardless of contents; whether the shard portion specifically got filed or
     dropped is never surfaced back to the sender through any mechanism.
   - **This is Bug 99's pattern, not a new class of concern.** A coercer using a controlled sender to
     probe for a depth-conditional difference is exactly what Bug 99 already tracks; the resolution is
     the same property checked here — every layer behaves identically, nothing to distinguish.

   **Correction made along the way: shard confirmations and manifests are not "non-shard payloads" and
   were never actually part of this open question.** First pass at this wrongly claimed no
   acknowledgment mechanism exists for shard custody at all — false; `ShardStatus.confirmed` and
   `bekSetupState`'s `waitingForConfirmations` are real, visible UI state. Checked properly:
   `buildCustodyManifest` is called unconditionally from `ComposeViewModel.swift` on every outbound
   bundle to a contact, the same "attached to every send" shape `mismatchHandbackOps` uses for shard
   returns. A manifest dropped or misattributed to the wrong depth self-corrects on that trustee's very
   next ordinary message — a different mechanism than shards' explicit handback retry, same safety
   property. Confirmations and manifests belong in the same "already safe to drop" bucket as shard
   returns, not the messages/prekeys bucket this item was actually asking about.

   **Net: no deferred-storage mechanism needed for either remaining category.** The item's own
   original concern — that deferring means "a cross-layer container again unless it too is slotted" —
   doesn't need resolving, because neither messages (excluded from the gate) nor prekeys (self-healing)
   ever needed deferral in the first place.

7. **Whether `CustodyShard` folds into this container — settled 2026-09-06: yes, keyed by the
   trustee's own depth, closing two previously-separate questions at once.**

   **Two questions this item was actually carrying, not one.** (a) The row-count leak —
   `CustodyShard`'s own doc comment already concedes it: *"Cold-disk forensics learns 'Bob holds N
   shards' — nothing about which contacts those shards belong to."* The contact-linkage half is
   mitigated; the row count is not, readable with no key on an unlocked device — the identical leak
   class S8 names for vault entries, left open on the trustee side of this whole redesign. (b)
   `LayerStore.md`'s own deferred question: if the *trustee* is coerced into their own duress layer,
   should shards they hold for other people become inaccessible to their coercer, the same way their
   own contacts and vault entries already would?

   **Why they resolve together.** `CustodyShard` lives on the trustee's device — a separate install
   from whoever the shard belongs to — so "folding in" can't mean literally joining the owner-side
   container (scoped to *this* device's own 32 depths). It means: on any device also acting as a
   trustee for someone else, store custody shards under the same recovery-buffer key and the same
   fixed-slot mechanism this device already needs for its own recovery machinery. Once framed that way,
   "depth" naturally means the **trustee's own depth**, not anything about which of the owner's depths
   a shard is for. Stamp each incoming custody shard with the trustee's current depth at the moment of
   receipt — the same way contacts and vault entries are already depth-stamped at creation — and it
   becomes accessible only when the trustee is back at that same depth later.

   - **Closes (a):** each of the trustee's 32 depth-slots pads to a fixed cap, indistinguishable
     whether it holds 0 shards or the max — the same fixed-slot technique used everywhere else in this
     design, organized by the trustee's depth instead of by owner.
   - **Closes (b):** a coercer holding the trustee's phone at their duress depth genuinely cannot see
     or reveal shards held for others at the trustee's real depth — they sit in a slot the coercer's key
     doesn't open, structurally, not by app-code discretion choosing not to show them.

   Nothing here requires knowing which depth of the *owner's* device a shard is for — that's the
   owner's own business, tracked in their own `shardMetadata`. The trustee's device only ever holds an
   opaque blob; the only depth that matters to the trustee's own protection is theirs.

   **Per-depth capacity — sized 2026-09-06.** Fixed-width shape for the stored `SignedAttribute`
   payload, one caught correction along the way: `signature` is documented as **DER-encoded**
   ECDSA-P256 (`SignedAttribute.swift`) — variable-length by construction (ASN.1 `INTEGER` encoding
   adds a leading zero byte to `r` or `s` whenever its high bit is set), the same class of mistake as
   `distributedAt` earlier in this design. Fix: store the *raw* `r‖s` representation (fixed 64 bytes)
   instead of DER — CryptoKit's `P256.Signing.ECDSASignature` verifies identically regardless of which
   representation it was constructed from, so this is a lossless conversion at write time, not a
   behavior change.

   | Field | Bytes | Note |
   |---|---|---|
   | owner identity hash | 32 | SHA-256, existing |
   | `id` (UUID) | 16 | |
   | `label` | 256 | fixed cap, UTF-8, zero-padded |
   | `value` (shard bytes) | 33 | 1 x-coordinate + 32-byte share, per `ShamirSecretSharing` |
   | `category` | 1 | `UInt8` tag, matches `ShardStatus`'s pattern, not the enum's string rawValue |
   | `signature` | 64 | raw `r‖s`, **not** DER |
   | `createdAt` | 8 | `UInt64` epoch seconds |
   | `expiresAt` | 9 | 1 presence byte + 8-byte value, always both — same pattern as `distributedAt` |
   | `entryID` | 17 | 1 presence byte + 16-byte UUID |
   | **Total** | **436** | — |

   **Capacity: 32 entries/depth-slot**, matching item 2's vault-entry cap for the same "how many
   different relationships" shape — not derived from CustodyShard-specific volume, a reused
   convention.

   **`formatVersion`: `UInt16` (2 bytes), once per depth-slot, not once per entry.** Same mechanism as
   the BEK `Payload` (`VAULT_KEY_LAYERING.md` item 3) and the same reason: the whole slot is always
   read and re-sealed together at migration, so every entry in it shares one version by construction —
   a per-entry field would be redundant and cost bytes × capacity for nothing.

   **Per depth-slot: `2 + (436 × 32) = 13,954 bytes`.** Container total per depth:
   `42,111 + 13,954 = 56,065 bytes` (supersedes item 5's 42,111 figure above).

   **Not yet implemented.** Design-only, matching the rest of this branch.

8. **The `storePendingRestore` tombstone soft spot — settled 2026-09-06: fix it, reusing a pattern
   already proven one function over.** A downgraded build can still *arm* a restore against the
   sibling doc's tombstoned legacy row, because that one site uses `try?` where its three siblings use
   `try` — `alreadyHasBEK` reads false against filler, since the tombstoned row's GCM auth failure gets
   swallowed into `nil` instead of propagating. Arming is this container's action, even though the
   check reads the other container's row.

   **Bounded, checked before deciding to fix rather than accept.** Only manifests on the narrow
   combination of migrated-then-downgraded — a device never touched by the new format still correctly
   detects its own real BEK. Even then, only *arming* succeeds; completion still can't, since
   `reconstructBEK` (the sibling that correctly uses `try`) will always fail against the same
   tombstoned row. No data loss. No oracle either: arming behaves identically regardless of which
   build is running, so it creates no build-detectable or depth-detectable difference.

   **The fix, and why it's worth doing rather than documenting as accepted:** `setupBEK()` already
   solves this exact problem, for the exact same row, one function over — it checks row *presence*
   (`existing.isEmpty`), not decryptability. `storePendingRestore` should do the same instead of
   attempting a decrypt and swallowing the failure: if a `BackupEncryptionKey` row exists at all —
   tombstoned filler or not — treat that as "already has a BEK" and refuse to arm, matching how the
   other three sites already behave. Not a new pattern to design, just reusing one already proven in
   the same migration. Small, low-risk change, which is why "accept as documented" isn't the better
   call here the way it might be for something costlier.

   **Not yet implemented.** Design-only, matching the rest of this branch — kept that way
   deliberately even though the fix itself is small enough to implement directly.

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

**Flagged 2026-09-11, not resolved here — possible internal inconsistency, cross-referenced from
`bugs.md` Bug 99.** This table's Bug 99 row qualifies its subsumption with "except the pending-file
tag," implying a standalone `.occbak` still exists and still needs a depth tag on it. But the very
next row, 100 r3, already says the opposite for the same file: "moot once §5 slots the contents" — and
§6 item 5 (dated 2026-09-06/07, later than this table's own undated entries) settles exactly that:
backup contents, shard buffer, and arming state all move into the shared-pool slots together, at which
point there's no standalone pending file left to tag at all — the depth is implicit in the slot. If
§6 item 5 is the final word, the Bug 99 row's qualifier is a leftover from before that item settled
and should read simply "open — subsumed here in full." Not corrected in place because it isn't fully
certain which of the two statements is the stale one without reconstructing the exact order these
were written in — flagged for whoever next touches Stage 4 to settle, not asserted as resolved.

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

[`VAULT_BACKUP_GUIDE.md`](VAULT_BACKUP_GUIDE.md), [`VAULT_SSS_GUIDE.md`](VAULT_SSS_GUIDE.md) — the
spec docs for the restore/shard behavior this design replaces. Keep their own "Secure Mode" closing
sections pointed here as this design's decisions land, the same as `VAULT_KEY_LAYERING.md`.

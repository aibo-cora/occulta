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

### 2.1 Concrete design, 2026-09-11 — where the gate actually hooks in, and a correction to the
framing above

**See `decisions.md`** (`Docs/General/`) for the short, scannable version of the
drop-all-kinds decision below — this section carries the full reasoning trail.

**Refines rather than follows the paragraph above: the gate should not live inside `identifyOwner`
at all.** That function (`Contact+Manager.swift:1550`) resolves the sender of *every* inbound bundle
— messages, prekeys, shard operations alike — and §6 item 6 already settled that messages and
prekeys must **not** be depth-gated the same way shards are (excluded from the gate entirely, and
self-healing by regeneration, respectively). Putting the check there would mean threading an
exemption back out for every non-shard caller, exactly the scope creep §4's "known scope creep" note
already warns about. The gate belongs on the shard-specific path instead.

**Rejected: checking inside `VaultManager.acceptReturnedShard` directly.** First pass at this
proposed resolving `senderIdentifier` to its `Contact.Profile` at the bottom of the call chain, where
`currentDepth` is also already a parameter. Caught before being built: `VaultManager` has no
`ContactManager` dependency today, and this would be the reason to add one — a real change to
`VaultManager.init` and every construction site across the app and tests, not a self-contained
addition to one function.

**Rejected: threading a `senderVisibleAtCurrentDepth: Bool` parameter down through
`handleInbound` → `handleHandback` → `acceptReturnedShard`.** Avoids the new dependency above, but a
required parameter breaks ~20 existing direct call sites in `ShardCustodyTests.swift`,
`ShardManifestTests.swift`, `ShardHandbackAttestationTests.swift`, and
`InboundShardCustodyDuressTests.swift`; a parameter defaulting to `true` avoids breaking them but
fails **open** — any future call site (test or production) that omits it silently bypasses the gate.
Neither shape was acceptable for something security-relevant.

**Built: filter the `shardOperations` array before it ever reaches `handleInbound`, at the one place
(`OccultaApp.swift`) that already has both `contactManager` and `currentDepth`.** No signature changes
anywhere in `ShardCustodyManager` or `VaultManager` — none of the existing call sites needed to
change, and there is no parameter to omit or default, so there's nothing to fail open on.

**Drops every shard op kind — `.distribute`, `.replace`, `.handback` alike — not just `.handback`,
revised 2026-09-11.** The first pass here scoped the drop to `.handback` only, on the reasoning that
`.distribute`/`.replace` (trustee-side custody storage) had no retry mechanism and dropping them
risked permanent shard loss. **That reasoning was wrong — corrected the same day, before it shipped.**
`PendingShardDistribute+Model.swift`'s own header claimed "deleted on send (fire-and-forget)"; that
was stale, corrected 2026-09-12 to match this section. `ShardCustody+Manager.swift`'s
`queueDistribute` doc comment says plainly: *"Row is deleted
only when the trustee's `custodyManifest` confirms the ID (not on send), enabling automatic retry on
bundle loss."* Checked directly against the code, not just the comment: `pendingDistributeOps`
(building the outbound `.distribute`/`.replace` ops) is a pure fetch with no delete anywhere in it;
the row is only ever removed in `processInboundManifest`, and only once the trustee's own
`custodyManifest` shows the shard ID present. If a trustee's device drops an incoming `.distribute`
(never creating the `CustodyShard` row), that ID simply never appears in that trustee's own outbound
manifest, so the owner's `PendingShardDistribute` row is never confirmed and keeps re-offering the
same op on every subsequent bundle — durable, automatic retry, the same property `mismatchHandbackOps`
provides for `.handback`, just implemented as owner-side persistence instead of trustee-side
re-offering. With the data-loss objection gone, dropping all three kinds is strictly better: a coerced
session structurally cannot cause *new* custody data to be written for a hidden owner at all, not
just cannot see it — complementary to §6 item 7's not-yet-built trustee-depth partitioning, not a
substitute for it, since pre-existing rows from before the session are unaffected either way.

**Placement: an instance method on `OccultaApp`, not a free function.** An earlier draft factored
this as a free function specifically so it could be unit-tested without a `ModelContainer` — while
building that version, a `static func` declared *inside* `struct OccultaApp: App` turned out to be
invisible to `@testable import Occulta` from the test target (`error: type 'OccultaApp' has no
member ...`, reproduced consistently even after clearing all caches; moving the identical function
to file-scope fixed it immediately — apparently specific to `static` members on a `@main`-attributed
type under this toolchain's explicit-module build, not anything wrong with the code). Moved back
to an instance method on request. Consequence, accepted: constructing an `OccultaApp` instance builds
a real, on-disk `ModelContainer` and runs live migrations, so this is genuinely not unit-testable in
isolation — covered by manual/integration verification instead, the same limitation the visibility
resolution already had. The dedicated unit test file this earlier draft added was deleted rather than
left describing coverage that no longer exists.

**The combined method — visibility resolution and the drop, one place** (`OccultaApp.swift`, private
instance method, next to `purgeOrphanedGroupsIfAtRealDepth`):

```swift
private func filterShardOperations(
    _ ops: [OccultaBundle.ShardOperation]?,
    from senderIdentifier: String
) -> [OccultaBundle.ShardOperation]? {
    guard
        let sender   = try? self.contactManager.fetchContact(by: senderIdentifier),
        let localKey = try? Manager.Key().createHybridLocalEncryptionKey(),
        sender.isVisible(atDepth: self.security.currentDepth, usingKey: localKey)
    else { return nil }
    return ops
}
```

**At both call sites (`OccultaApp.swift`, the `.v3fs`/group and the legacy branch), the
`shardOperations:` argument to `handleInbound` becomes:**

```swift
self.filterShardOperations(
    recipShardOps ?? sealed.shardOperations,  // or sealed.shardOperations at the other site
    from: ownerID
)
```

**Key domain, worth stating explicitly since it's easy to assume otherwise:** `isVisible(atDepth:)`
decrypts `originDepth`/`visibleThroughDepth` under the **local DB key**
(`Manager.Key().createHybridLocalEncryptionKey()`, the bare `Data.decrypt()` extension's own
derivation) — not the recovery buffer key `acceptReturnedShard` separately derives for
`ReconstructShard` rows, and not the vault key. Both are ambient, device-unlock-gated, no
biometric, so the gate adds no new availability constraint — it's exactly as available as
`storeRestoreShard` already is.

**What this deliberately does not touch:** `handleHandback`'s own Branch A/B signature verification —
an op filtered out here never reaches that code at all, so there's no verification wasted on it.
Message and prekey processing, different call paths entirely, per §6 item 6. The trustee-*side*
`handleDistribute`/`handleReplace` when *this* device is the one receiving custody on someone else's
behalf are untouched by this specific gate too (item 7's own, separate "keyed by the trustee's own
depth" mechanism covers that direction) — this gate is about what *this* device accepts as the owner,
not what it stores as a trustee for others.

**Migration: none.** No schema change, no new persisted field — this reads fields
(`originDepth`/`visibleThroughDepth`) that already exist and are already populated.

**Tests: none dedicated, by design — see the placement note above.** `InboundShardCustodyDuressTests.swift`'s
existing tests call `ShardCustodyManager.handleInbound` directly, one layer below this filter, and
are unaffected: they continue to assert that `ShardCustodyManager` storage itself is unconditional,
which is still true — the depth decision now happens one layer up, in `OccultaApp`, before
`ShardCustodyManager` is ever reached, not inside it.

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
| 3 | Sender-visibility gate on inbound processing (§2, concrete design in §2.1, 2026-09-11), with the drop/defer decision from §7 | a shard from a contact hidden at the current depth is not banked; a trustee's retry lands when the user returns to their depth |
| 4 | Per-depth restore state: arming, sealed backup contents, shard buffer, per-depth cancel | arming in duress does not block depth 0; cancel clears only its own layer |
| — | ~~As a fixed-slot file~~ — **superseded 2026-09-11 (§6 item 9: rows, not a file), 2026-09-12 (§6 item 9.2: one sealed array on a new `Vault` model), and 2026-09-13 (§6 item 9.3: depth-indexing abandoned outright — `PendingShamirSecretRestore` becomes its own `@Model`, keyed by the secret's own identity, generalizing past BEK).** 9.3 also found and closed a counting oracle (`bugs.md` Bug 122, resolved same day) by deciding never to cap this container at all — permanent, not a placeholder. Implementation still reflects the superseded 9.1 shape, not yet rebuilt. |
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

**Proposed answer, 2026-09-11 — §6 item 9: there may be no "where it lives" question left to
re-decide, because there's no file proposed to live anywhere.** Rather than re-settling this section
against whatever the vault-key side's file membership turns out to be, item 9 proposes retiring the
file side of this container entirely — rows, following `VAULT_KEY_LAYERING.md` item 14's own BEK
migration — which would make this section moot rather than merely in need of new numbers. Not yet
decided; see item 9 for what's still open before that's settled.

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

9. **Proposed 2026-09-11: retire the file entirely — this container as SwiftData rows, not a
   shared-pool file, following `VAULT_KEY_LAYERING.md` item 14's own BEK migration.** Prompted by a
   direct question: does this container have to be a file at all, given the sibling doc's BEK array
   just moved off file storage onto rows for the same class of reasons item 5 above assumed only a
   file could provide. It doesn't, and checking what's *actually* still file-based here turned up
   less than the rest of this document assumes.

   **Three of this container's four pieces are already rows, not files, in production.**
   `ReconstructShard` (`ReconstructShard+Model.swift`) has held BEK restore shards since Bug 100
   remedy 2, 2026-08-27 — well before item 14 or this proposal. `CustodyShard`
   (`CustodyShard+Model.swift`) has never been a file. Stage 4's own plan above (moving both into a
   fixed-slot *file*) would have been a regression for the shard buffer specifically, undoing
   something already shipped. Only the arming flag and the pending backup-contents snapshot
   (`backup-import-cache.occbak`, `storePendingRestore`) are genuinely still file-based today.

   **Why rows alone don't already close this, and what does — the same answer item 14 already
   proved.** Bug 100 remedy 2's own text concedes moving to rows only *reduces* the row-count leak
   Stage 4 was meant to close outright: *"an examiner who opens the store can still count rows...
   A reduction, not an elimination."* That gap is exactly what item 14's eager-filler-row baseline
   closes for `BackupEncryptionKey` — pad row count to a constant floor regardless of real usage,
   let real content claim a filler row rather than the row count ever tracking reality, uncapped
   beyond the baseline. Applying that identical pattern here — not a new mechanism, the one already
   proven and tested — closes what rows alone left open, without needing a file to do it.

   **Per-component design, each mirroring `BackupEncryptionKey`'s three-state shape (filler/live/
   orphaned, one-way transitions, both fields present at every state so nothing is a free
   zero-decryption signal):**

   - **Shard buffer (`ReconstructShard`).** Add the filler-row baseline directly to the existing
     model rather than replacing it — it already has the right shape (one row per shard, sealed
     under the recovery buffer key). What it's missing is padding: today, zero shards banked means
     zero rows, which is itself informative. Needs a baseline count per depth chosen deliberately —
     **not** the Shamir ceiling (255) §6 item 5 above sized the *file slot* to. That number was sized
     for "the largest a legacy distribution could ever be," a worst-case-capacity question a fixed
     file slot has to answer once; a filler-row baseline is a different question — "how many rows
     should exist regardless of activity," the same question item 14 answered as 32 for BEK by
     analogy to `AppLayerConfig.maxDepthCount`. This container has no equivalent existing constant
     to anchor to and needs its own answer, not a borrowed one — left open below, not decided here.
   - **`CustodyShard`.** Same treatment, keyed by the *trustee's own* depth per item 7's already-
     settled design — a filler-row baseline per trustee-depth closes item 7's own row-count-leak half
     (part (a) of that item) the same way, without needing item 7's originally-envisioned fixed-slot
     array at all.
   - **Arming state + pending backup contents — one new model, not two.** Both are per-depth,
     both need the recovery buffer key (arming and holding a restore must work while the vault is
     locked), and arming state is small enough (§6 item 5's own estimate: *"timestamp, state enum...
     ~64 bytes"*) to live as a field alongside the snapshot rather than earning its own row. One row
     per depth: `depth: Data?` (encrypted, filler when unclaimed — the row's claim state), `state:
     Data?` (encrypted arming timestamp + state enum, filler when unclaimed), `encryptedSnapshot:
     Data` (the already-sealed `.occbak` bytes as delivered — this container never decrypts them,
     only holds them until `VAULT_KEY_LAYERING.md` §7 Stage 5 reconstructs the BEK and hands them to
     `importBackup`). **Correction to this proposal's own first framing:** §6 item 5's per-entry
     sizing math (1,051 bytes × 32) computes a *capacity ceiling* for this field — how large a real
     `.occbak` payload could plausibly need to be — it does not mean the snapshot should be decoded
     into 32 separate per-entry rows at arming time. It can't be: the snapshot is one sealed unit
     under whichever BEK produced it, unreadable until that BEK is reconstructed, so there is nothing
     to decompose into rows before then. One row per depth, one padded blob field, exactly
     `BackupEncryptionKey.encryptedPayload`'s own shape.

   **This resolves §7's own flagged ambiguity about Bug 99, not just §5's stale file-membership
   count.** That section's "except the pending-file tag" qualifier assumed a standalone pending file
   that still needs a depth tag on it. Under this proposal there is no pending file at all — the
   depth is which row it is, the identical property that already makes BEK's own per-depth rows work
   without a tag. If this proposal is adopted, that qualifier should simply come off.

   **What's still genuinely open, not resolved by this proposal:**
   - **Filler-row baseline counts** for shard-buffer and pending-snapshot rows — a real sizing
     decision, not automatic from item 14's precedent, since this container's usage shape (shards
     arrive continuously during a restore; a restore is armed once and holds one snapshot) differs
     from BEK's (configured once per depth, rarely touched again).
   - **The row-count-hiding property this buys is bounded by the baseline, same limitation item 14
     already accepted for BEK** — past the baseline, row count starts tracking real activity again.
     Acceptable there because BEK rows are rarely created; needs its own justification here given
     shards arrive far more often.
   - **§3's per-depth cap reasoning is unaffected either way** — "a cap is only safe once the buffer
     is per-depth" holds whether "per-depth" means a file slot or a filler-row baseline; this
     proposal doesn't reopen that question, just changes what "per-depth" is built from.
   - **This proposal does not provide the cap `bugs.md` Bug 96 item 2 is waiting for, flagged
     2026-09-12.** That item deferred adding a real bound to the shard buffer on the assumption a
     fixed-slot design would give one "for free" once built. A filler-row *baseline*, uncapped
     beyond it, is a different property — it hides row count up to the baseline, the same
     forensic-signal problem item 14 closed for BEK, not the resource-exhaustion problem item 2 is
     actually about (confirmed still live: `restoreShardFileIsBounded`,
     `VaultRestoreTrustTests.swift:587`, is a `withKnownIssue` showing 300 junk shards from 300
     distinct senders bank without limit). Whoever builds this needs to decide a real cap for the
     shard buffer specifically, on top of whatever baseline gets chosen — §3's per-depth-safety
     argument for capping still applies and still has to be made, it just isn't made by this item.

   **Supersedes, if adopted:** §4 Stage 4 as written (a fixed-slot file); §5 in full (there is no
   file left to decide "where it lives" for); §6 item 5's slot-size numbers stay useful as capacity
   ceilings for the padded row fields above, but stop being *file-slot* sizes. **Not yet decided** —
   proposal only, matching this document's own "design, not built" status; the baseline-count
   question above blocks calling this settled.

### 9.1 Concrete design, 2026-09-12 — the baseline/cap question settled, the rest of Stage 4's shape
specified

**Settles the baseline-count question item 9 left open, by not letting it be two questions.** Rather than
choosing a smaller filler baseline and a separate, larger hard cap, both are the same number: **255**, the
Shamir ceiling §6 item 5 already computed for the old file slot. A smaller baseline (32, by analogy to
every other baseline in this design) would leave the 32-255 range genuinely unhidden — the 33rd real shard
banked for a depth is a bare, undecryptable-but-still-visible extra row past whatever the baseline claims
to guarantee, the identical "row count tracks real activity past the baseline" gap item 14 accepted for
BEK, except shards arrive far more often than BEK setups do, so it would bite sooner and harder here.
Matching baseline to the true ceiling closes it outright: real usage can never exceed 255 (nothing could,
by construction of the scheme), so prefilling to 255 makes row count constant across the entire range that
could ever be real, not just up to an arbitrary smaller number. Cost, stated plainly: up to 255 filler rows
× `AppLayerConfig.maxDepthCount` (32) possible depths = up to 8,160 filler rows for this one piece,
created once at first launch — heavier than every other baseline in this design, and worth it only because
the alternative doesn't actually deliver what a baseline is for.

**Corrected 2026-09-12, before any of this was built: filler rows for the shard buffer cannot be
pre-organized by depth at all — the pool is one shared, undifferentiated set, not 255-per-depth.**
`PendingVaultRestore`'s `depth` (below) is a separate column sealed under the local key, so it can be assigned
at row-creation time, before any real content exists — exactly like BEK's own rows. `ReconstructShard`'s
`depth` lives *inside* `Payload`, sealed under the recovery buffer key alongside everything else (see
below) — it genuinely cannot be known or assigned until real content is written, so there is no way to
pre-create "255 filler rows for depth 3" the way BEK pre-creates "row 3 of 32." The working design instead
is **one shared pool of 8,160 rows (255 × 32), sized so every depth could reach its own 255 cap
simultaneously in the worst case** — real and filler mixed, unassigned to any depth until claimed.
"Claiming" means finding any row whose `encryptedPayload` fails to decrypt at all (genuine filler) and
re-sealing *that row*, reusing its `id`, rather than inserting a new one — the same `claimFillerRow`
mechanic BEK already uses, applied to a shared pool instead of one row per depth. The filler-row
insertion-order-shuffling concern this paragraph originally raised does not apply to this piece at all —
there is no depth-order to a set of rows that have no depth until claimed. It still applies to
`PendingVaultRestore` below, which is where it's now stated.

**A structural consequence of this, not designed for deliberately but worth stating since it differs from
every other piece in this section: the shard buffer is immune to `bugs.md` Bug 120 in a way
`PendingVaultRestore` and BEK are not.** Bug 120's leak needs a row's depth to be knowable more cheaply
than its content — true for BEK/`PendingVaultRestore`, where depth sits under the local key while content
sits under a different, "bigger" key. Here, depth and content share one key. An examiner without the
recovery buffer key cannot attribute a changed row to any depth at all, not even the weak "which row
changes most often" version of the signal, because there is no cheaper path to depth than the one full
content already requires. Not a substitute for resolving Bug 120 generally — `PendingVaultRestore` two
paragraphs down still needs it — but this piece specifically doesn't inherit the problem.

**Shard buffer: extend `ReconstructShard.Payload`, not the SwiftData column.**

```swift
struct Payload: Codable {
    let entryID: UUID
    let attrID:  UUID
    let signedAttribute:  SignedAttribute
    let senderIdentifier: String
    let attestation:      SignedAttribute?
    let depth:            Data?     // NEW — DepthCodec-encoded, nil for per-entry rows
}
```

`depth` lives *inside* the encrypted blob, not as a new plaintext SwiftData column — this is what lets it
carry no forensic signal at all regardless of presence or value, the same reasoning `PendingShardDistribute`
and `CustodyShard`'s own payloads already rely on for their own optional fields. **Caught during this
design, corrected before it was ever written as code:** a raw `Int` for `depth` was the first draft, and
`JSONEncoder` writes an `Int` as decimal ASCII text — `1` serializes one byte shorter than `10`, which
serializes shorter than anything ≥ 100. AES-GCM preserves that difference straight into `encryptedPayload`'s
ciphertext length, which would have made a BEK-restore row's on-disk size vary by which depth it belonged
to — a coarser version of exactly Bug 85 (`Int.max` spelling 19 bytes against an ordinary depth's 1), the
bug `DepthCodec` exists to close everywhere else in this codebase. Fixed the same way everywhere else is:
`depth` is `DepthCodec.encode`/`.decode`'d — always exactly 2 bytes — before being placed in the payload, so
every BEK-restore row's serialized size is depth-invariant. `JSONEncoder` emits `Data` as base64, and base64
of a fixed 2-byte input is itself a fixed 4 characters, so this holds through the outer JSON encoding too.

Populated only for the BEK-restore subset — same test as today, `entryID` resolving to no real
`VaultEntry` — set from `currentDepth` at insertion. Requires threading `currentDepth` into
`storeRestoreShard(_:attestation:senderIdentifier:)`, which has no depth parameter at all today (the exact
gap `bugs.md` Bug 99 already names: *"`storePendingRestore` ... still has no depth parameter at all"*).
`acceptReturnedShard` already receives `currentDepth`, so this is a pass-through, not a new dependency.

Every function that currently treats the BEK-restore rows as one global pool gains a depth filter:
`bekRestoreRows`, `loadRestoreShards`, `clearBEKRestoreShards`, and `attemptBackupRestore`'s per-`entryID`
grouping — each scoped to the depth being acted on, so depth 2's collection is invisible to and independent
of depth 5's, closing the exact gap §1's table names (*"Restore shard buffer... shards cannot be
attributed to a layer before reconstruction"*).

**Cap: 255 distinct-sender rows per depth, enforced by rejecting past it, never evicting.** Once a depth's
live-row count (real, non-filler) reaches 255, further distinct senders are silently dropped — not stored,
not counted, no error surfaced. Eviction was considered and rejected: evicting the oldest row to make room
is itself an attack — flood a depth's buffer to knock out a real trustee's already-banked share. Rejection
has its own honest cost, stated plainly: a real trustee's share arriving *after* an attacker has already
filled the cap with junk is dropped identically to the junk. This closes `bugs.md` Bug 96 item 2
(confirmed still live going into this design: `restoreShardFileIsBounded`, `VaultRestoreTrustTests.swift:587`,
a `withKnownIssue` showing 300 junk shards from 300 distinct senders bank without limit) — 255 is far above
any realistic trustee count (single digits, threshold ≥ 2), so no legitimate distribution is ever at risk
of hitting it, and it can never reject a genuine share from *any* distribution, past or future, because 255
is the hard ceiling the underlying scheme's 1-byte x-coordinate allows — not a guess, a proof.

**Arming state + pending snapshot — one new model, `PendingVaultRestore` (named for the vault backup it
restores, since other restore kinds may exist later), one row per depth, mirroring `BackupEncryptionKey`'s
three-state shape exactly (filler → live → orphaned, one-way transitions, every field always present so
nothing is a free zero-decryption signal):**

```swift
@Model
final class PendingVaultRestore {
    var id:               UUID
    var depth:            Data?     // local key, DepthCodec, exact-match — claim state
    var deletionToken:    Data?     // local key, live/orphaned sentinel
    var encryptedPayload: Data      // recovery buffer key, fixed-width RestoreStateCodec
}
```

**Filler-row insertion order must be shuffled across depths, not depth-by-depth — moved here from the
shard-buffer discussion above, since this is the piece it actually applies to.** Unlike `ReconstructShard`,
`PendingVaultRestore.depth` is assignable at row-creation time (sealed under the local key, not buried inside
the same blob as content), so all 32 rows could in principle be created depth-ordered — row 0 for depth 0,
row 1 for depth 1, and so on. If they are, SQLite rowids (and likely on-disk layout) correlate with depth
by construction, with no decryption needed to notice which position moved. Insert all 32 rows in a
shuffled, non-depth-ordered sequence at launch instead.

**`depth`/`deletionToken` sealed under the local key, not the recovery buffer key — deliberately, to reuse
the one working pattern rather than assume a new one is safe.** `Manager.Security`'s eventual orphaning
code and this model's own writes need to agree on what they're reading and writing without either one
going through `VaultManager`'s or `Manager.Security`'s own *injected* `keyManager` — the exact trap
`VAULT_KEY_LAYERING.md`'s BEK design already documents (two independently-injected `TestKeyManager`
instances could disagree on anything derived through them). The recovery buffer key would also be available
without biometric gating, which is what made it tempting to just reuse for everything here, but nothing
establishes yet that `VaultManager`'s and `Manager.Security`'s own copies of it agree in every test
configuration the way the ambient local key is already proven to. Matching BEK's already-safe split costs
nothing and avoids introducing a new, unverified assumption.

**`encryptedPayload` sealed under the recovery buffer key — the one deliberate divergence from copying
BEK's template.** Arming and shard collection both need to work while the vault is locked, which is this
whole container's reason for existing as a second key domain in the first place (§0's intro). A fixed-width
`RestoreStateCodec` (byte layout not yet specified) holds:
- an armed-flag + timestamp, always present, filler-random when not armed — the same "presence byte +
  fixed-width value, always both" convention `CustodyShard`'s own `expiresAt`/`entryID` fields already use
  (§6 item 7);
- a length-prefixed, zero-padded snapshot of the `.occbak` bytes, padded to the same per-entry ceiling
  `VAULT_KEY_LAYERING.md` item 2 already computed for vault entries (1,051 bytes/entry, the same dynamic
  32-multiple growth mechanism) — not a separately-invented number, since a pending-restore snapshot *is*
  every entry visible at the arming depth, the identical set item 2's own field already describes.

**Claimed once per depth, like BEK — not reclaimed on cancel or completion.** A depth's row stays "live"
once first armed; only its *content* (armed-flag, snapshot) resets on cancel or completion, so the same
depth can arm again later without the row itself needing to cycle back through filler. This differs from
BEK's own lifecycle (set up once, essentially permanent) because arming genuinely is a repeatable action at
one depth across a session — the row's *claim* is permanent per depth, but not everything about its
content is.

**Per-depth cancel:** resets the depth's `PendingVaultRestore` payload (armed-flag and snapshot cleared, row
stays live and claimed) and deletes that depth's own depth-tagged `ReconstructShard` rows (matched by the
`depth` field above), leaving every other depth's independent restore attempt completely untouched. This is
the Stage 4 acceptance criterion §4's table already names: *"cancel clears only its own layer."*

**What this does not settle — flagged, not decided:**

- **Whether these new rows reseal on write.** Writing one depth's `PendingVaultRestore` row or claiming one
  depth's `ReconstructShard` filler row, the way everything above is specified, leaves every other depth's
  stored bytes untouched — exactly the property `bugs.md` Bug 120 names as a cross-cutting, unresolved leak
  (write frequency across snapshots reveals which depth is used most, likely identifying the real one).
  This design inherits that leak rather than closing it, same as every other per-depth container in the app
  already does. Not decided here — Bug 120 is where this gets resolved, for this container and every other
  one, not piecemeal per feature.
- **Orphan-on-deactivation wiring.** Nothing currently calls anything for this container from
  `Manager.Security.deactivateSecureMode`/`forceDeactivateForRecovery`. A freed depth's leftover armed
  restore (snapshot, collected shards) would otherwise survive into a later, unrelated session reactivating
  at the same depth number — the identical class of bug Bug 110/118 closed for `VaultEntry`/
  `BackupEncryptionKey`, not yet closed here. Needs a new `orphanPendingVaultRestores`-type function, same
  pattern as `orphanBackupKeys`, called alongside it.
- **`RestoreStateCodec`'s exact byte layout.** The shape above (armed-flag + timestamp + padded snapshot)
  is specified; the precise offsets, following `Backup.PayloadCodec`'s own versioned-format discipline, are
  not.
- **§8's migration** needs rewriting for rows instead of slots — the destination (slot 0 → depth 0) and the
  "commit first, then destroy the source" ordering both still apply, but every mention of "slot" becomes
  "claim the filler row for depth 0."

**Supersedes, if adopted:** the "Not yet decided" close of item 9 above, for the baseline/cap and the
overall shape — those are now decided. The four items immediately above remain genuinely open.

### 9.2 Revised 2026-09-12 — one sealed array replaces the shared pool for BEK-restore shards

**Supersedes 9.1's shard-buffer half specifically — the `ReconstructShard.Payload.depth` extension, the
shared undifferentiated pool, and the filler-row-claiming mechanics all go away.** 9.1's own arming-state
model (`PendingVaultRestore`, then still a `@Model` row per depth) is not discarded — it absorbs the shard
slots too, becoming the one place this whole container's state lives. Prompted by a direct question: does
`PendingVaultRestore` need to be a SwiftData model at all, or can the whole thing be a `Codable` struct held
inside one sealed field, the same shape `backup-export-meta.dat` already uses successfully. It can, and
doing so closes two problems 9.1 left open rather than one.

**The new entity: `Vault`, one `@Model` class, one row, ever — living in `Vault+Model.swift` alongside this
domain's other supporting types (`VaultEntryType`, `ShardStatus`, `ShardRecord`, `ShardDistributionMetadata`),
not a new file.**

```swift
@Model
final class Vault {
    var id: UUID = UUID()
    var sealedPendingRestores: Data = Data()   // recovery-buffer-domain key; see below
}
```

One field. Its plaintext, once opened, is `[PendingVaultRestore]` — exactly 32 elements, always, index =
depth. `formatVersion` prefixes the encoding the same way `Backup.PayloadCodec` does, for the same reason
(a future shape change needs to keep reading the old one).

**`PendingVaultRestore` is now a plain struct, not a model — no `id`, no `depth` column, no
`deletionToken`.** All three existed to do things a *row* needs (identity independent of position, a
claim/orphan state a scan can find) that an *array element* gets for free:

```swift
struct PendingVaultRestore: Codable {
    var armedAt: Date?                     // presence byte + fixed value, always both — nil when not armed
    var distributionID: UUID?              // the BEK distributionID this depth is currently armed against
    var encryptedSnapshot: Data?           // the already-sealed .occbak bytes, padded to the item-2 ceiling
    var shards: [PendingRestoreShardSlot]  // exactly 255 elements, always
}

struct PendingRestoreShardSlot: Codable {
    var signedAttribute: SignedAttribute?
    var senderIdentifier: String?
    var attestation: SignedAttribute?
}
```

**Depth is array position, and that closes the exact problem 9.1 couldn't solve.** 9.1 needed `depth`
inside `ReconstructShard.Payload` because nothing else could tell a row's depth without opening it — a
genuine structural dead end, since a row can't be pre-assigned a depth it doesn't know yet. Here, there is
no equivalent problem: `pendingRestores[3]` *is* depth 3's entry, unconditionally, before anything is ever
written to it. No field to decrypt, no filler-vs-claimed distinction, no claiming mechanic at all — every
depth's slot exists from the moment `Vault`'s single row is first created.

**`distributionID` moves from per-shard-slot to per-depth-entry, a simplification 9.1 didn't have available.**
`storePendingRestore`'s own refusal rule (only one arming at a time per depth) means every shard slot filled
while a depth is armed belongs to the *same* distribution — there is never a second, competing `distributionID`
to disambiguate within one depth's 255 slots. 9.1's `ReconstructShard.Payload` needed `entryID` on every row
because rows from unrelated distributions could genuinely intermix in the shared pool; that population
doesn't exist here, so the field moves up one level and gets stored once instead of 255 times.

**255 stops being a counted cap and becomes a fixed array size — the identical number, a cleaner
mechanism.** "Reject once live count reaches 255" (9.1's phrasing) and "the array has 255 slots, find an
empty one or refuse" describe the same behavior; the array version needs no counting pass, since a full
array *is* the refusal condition. The Shamir-ceiling justification for 255 is unchanged — it's still the
hard mathematical bound so no genuine distribution can ever be truncated by it.

**Bug 120 closes for this whole container, not just the shard-slot piece — and by the strongest available
mechanism, not the weaker one 9.1 could only claim for part of it.** One field, one seal, one fresh nonce
per write: every write to *any* depth's arming state or *any* shard slot re-encodes and reseals the entire
32-entry array, so the ciphertext changes in full regardless of which depth or which slot actually moved —
the same property `ExportMetaSlotCodec` already has, and the property the old, deleted array-file design
had that rows-based storage kept losing throughout this whole document. 9.1 could only argue the shard-slot
piece was *immune* to Bug 120 (depth unknowable without the same key content needs); this is stronger —
depth isn't just unknowable, there's no separate ciphertext to diff at all below the level of the whole row.

**What doesn't change: per-entry PEK reconstruction, still `ReconstructShard`, completely untouched.** This
revision is scoped to the BEK-restore population only. `ReconstructShard.Payload.depth` (9.1's addition) is
now dead weight for that population specifically — nothing populates it once BEK-restore shards move here —
and should be removed once implementation catches up. Not done yet; flagging, not fixing here.

**Orphan-on-deactivation, restated for this shape:** "orphaning depth N" is no longer a token flip on a
row — it's clearing `pendingRestores[N]`'s fields back to their unarmed state (`armedAt = nil`,
`distributionID = nil`, `encryptedSnapshot = nil`, every shard slot's fields `nil`) and resealing the whole
array. `Manager.Security`'s eventual orphaning code needs `Vault`'s own row and the restore-vault-domain
key to do this — still not wired to `deactivateSecureMode`/`forceDeactivateForRecovery`, same open item 9.1
already named, now aimed at a different storage shape.

**Singleton discipline needed, mirroring `AppLayerConfig`'s own.** Nothing in SwiftData enforces "exactly
one `Vault` row" — that needs a fetch-or-create helper the same shape `Manager.Security.requireConfig()`
already provides for `AppLayerConfig`, not yet written.

**Implementation debt this creates, stated plainly:** the shard-buffer code already built and tested against
9.1's design (`claimBEKRestoreFillerRow`, `sealBEKRestorePayload`, the depth-scoped `bekRestoreRows`/
`loadRestoreShards`/`clearBEKRestoreShards`, the counting-based cap check in `storeRestoreShard`, all in
`Vault+Manager+ReturnBuffer.swift`) is superseded by this revision and will need replacing, not extending,
once implementation is redone against `Vault`/`PendingVaultRestore` instead. Not reverted yet — this section
records the design change; the code still reflects 9.1.

**What's still open, carried forward from 9.1 and not resolved by this shape change:** the exact byte
layout of the sealed encoding (shape specified, offsets are not); the filler-row-insertion-shuffling concern
from 9.1 is now moot outright (there is only one row, nothing to shuffle); §8's migration still needs
rewriting, now for "claim `pendingRestores[0]`" rather than either "slot" or "row."

### 9.3 Revised again, 2026-09-13 — depth-indexing abandoned entirely; a counting oracle found and left open

**Supersedes 9.2's `[PendingVaultRestore]`-array-inside-`Vault` shape outright, not just the shard-slot
half this time.** 9.2 fixed `ReconstructShard`'s depth-attribution problem by moving to one sealed array,
indexed by depth. That still assumed every secret being restored *has* a depth — true for BEK, not true in
general. A per-entry PEK restore is keyed by a `VaultEntry.id`, with no relationship to duress depth at
all; there is no slot in a 32-element depth-indexed array for it to occupy. Renaming `PendingVaultRestore`
to `PendingShamirSecretRestore` (below) committed to generalizing past BEK; the depth-indexed array never
actually could.

**The restore flow itself was reordered first, and that's what let `encryptedSnapshot` disappear.**
Original complaint: arming conflated two things — "start accepting shards" and "hold the `.occbak` file's
bytes for the entire waiting window," which could be days. Proposed fix: an explicit "start shard return"
action begins shard collection with no file present at all; the user opens the `.occbak` file only once
enough shares have arrived, and reconstruction (`Backup.reconstruct`'s GCM-tag-against-the-real-file check,
the actual defense against Bug 95's poisoned-share concern) happens synchronously at that moment, file and
shares both in hand together. The oracle that check provides is not lost — it fires later, once, instead of
being held open for days. Consequence: `encryptedSnapshot` (33,632 of `PendingVaultRestore`'s ~42,111
bytes-per-depth in 9.2's own sizing) is not needed at all; nothing in the collection phase ever touches
vault-entry content. `armedAt` was separately dropped — nothing in the reconstruction path reads a
timestamp, only whether collection is happening, and that turned out to already be redundant with other
state once traced through.

**Generalizing past depth means keying by the secret's own identity instead — `PendingShamirSecretRestore`
becomes a real `@Model`, not a struct inside `Vault`'s array:**

```swift
@Model
final class Vault {
    var id: UUID = UUID()
    @Relationship(deleteRule: .cascade, inverse: \PendingShamirSecretRestore.vault)
    var pendingRestores: [PendingShamirSecretRestore] = []
}

@Model
final class PendingShamirSecretRestore {
    var id: UUID = UUID()
    var attributeID:   Data? = nil   // local key — a BEK distributionID, a VaultEntry.id, or any future kind
    var deletionToken: Data? = nil   // local key — live/orphaned sentinel, same convention as VaultEntry/BackupEncryptionKey
    var shards:        Data? = nil   // restore vault key — sealed, padded [PendingRestoreShardSlot], 255 elements once decoded
    var vault: Vault?
}
```

`attributeID`/`deletionToken` sealed under the **local key**, matching `BackupEncryptionKey`'s own forced
split exactly — whatever eventually orphans these rows runs from `Manager.Security`, which never derives
the restore vault key. `shards` stays under the restore vault key, the same domain the shard content itself
already needed. `deletionToken` marks the moment the secret this row tracks is consumed (successfully
reconstructed) — orphaned in place, never deleted, same convention as every other soft-delete model in this
codebase. `shards` was briefly, mistakenly sketched as a plain `[PendingRestoreShardSlot]` — a real
stored-property array holding raw share bytes and sender identity with none of this app's own encryption
over it, caught before it shipped; `Data?` (sealed, padded, fixed-width once the codec exists) is the
corrected shape.

**Cost of this shape, once shards moved into `Data?`: this is a large row, not a small one.** Sizing the
255-slot `PendingRestoreShardSlot` array precisely (449 bytes/slot: presence tag + a 412-byte
`SignedAttribute`, reusing `CustodyShard`'s own §6 item 7 sizing, + 36-byte sender identifier) gives
**≈112 KB per row**, almost entirely `shards` — `attributeID` and `deletionToken` combined cost under 100
bytes. (Corrected 2026-09-13 from an earlier ≈211 KB/404-byte figure — `signature` was sized for a raw r‖s
signature where `KeyManagerProtocol.signData(_:)` actually returns DER, 72 bytes not 64. Then, 2026-09-14,
`bugs.md` Bug 124 removed the attestation field entirely — see below — cutting the per-row cost roughly in
half again, from ≈215 KB to ≈112 KB.)

**The attestation half of this layout was removed, 2026-09-14 — `bugs.md` Bug 124.** Tracing what Branch B
(attestation) actually proves turned up a broader gap it doesn't close: neither `distributionID` nor a
`VaultEntry`'s `entryID` changes when the trustee list changes without a full secret rotation, so a removed
trustee's original, genuinely-signed share stayed valid forever — via Branch A alone, no attestation
involved. Bug 124's remedy (regenerate the distribution id/value on every trustee-set mutation) makes stale
credentials inert by construction, at which point Branch B was doing nothing a direct current-trustee check
wouldn't do more cheaply — so `PendingRestoreShardSlot.attestation` and half of `SignedAttributeCodec`'s use
in this codec are gone, not just flagged. `PendingRestoreShardSlot` now carries only `signedAttribute` and
`senderIdentifier`. The shipped, tested Branch B mechanism in `ShardCustody+Manager.swift`
(`ShardHandbackAttestationTests`) is a separate, currently-live system — this removal is scoped to the
foundation-only model in `Vault+Model.swift`, which nothing calls yet; the shipped mechanism's own removal
is Bug 124's remedy landing, not yet done.

**Consequence: `Vault`'s "one seal covers everything" property — the mechanism that closed `bugs.md` Bug
120 for this container as a side effect of the storage shape — does not survive this move.** Independent
rows mean a write to one `PendingShamirSecretRestore` no longer touches any other. Two genuinely different
leaks were conflated while working through this, worth keeping separate:
- **Row count, at a single point in time** (how many are currently live vs. orphaned) — closed by
  orphan-in-place alone. A keyless examiner sees N total rows and cannot tell how many are live without the
  local key to read `deletionToken`.
- **Which row's bytes change, across multiple snapshots over time** — Bug 120's actual claim, and
  orphan-in-place does nothing for it. A byte-diff between two captures shows exactly which row moved, no
  key required at all, independent of what that row's content means.

The fix for the second one is the same mechanism the old, deleted array file already used and
`VAULT_KEY_LAYERING.md` item 7 already named: reseal *every* row, fresh nonce, on *every* write, so the
ciphertext changes in full regardless of which row actually changed. That still works here — but the old
array's version of this was cheap specifically because the population was fixed at exactly 32 slots forever.
`PendingShamirSecretRestore` rows are not fixed — they accumulate (orphaned, never deleted), so
reseal-everything gets more expensive the longer the device has been used, not a flat cost. A cap on total
row count (mirroring `VaultEntry`'s own 50-row cap-and-evict, oldest orphaned row evicted first) would bound
that cost — sizing it at a few candidate values: 10 rows ≈ 2.16 MB, 32 (matching BEK's own baseline) ≈
6.91 MB, 50 (matching `VaultEntry`'s cap) ≈ 10.79 MB. Not adopted — see below.

**A counting oracle found while working through the cap question, not yet resolved, and this is the most
important finding in this revision.** Capping only the *orphaned* population (evict oldest orphaned row
past N, leave live rows uncapped) leaves live rows exactly as exploitable as `bugs.md` Bug 96 item 2 already
found for the old design — except now each junk row costs ≈112 KB instead of a few hundred bytes, since
every `attributeID` that's never been seen before claims a full row. Capping *live* rows instead closes that,
but reopens something worse: **§3 of this document already named the exact failure mode** — *"a cap on a
shared buffer is a cross-layer denial channel"* — and generalizing this container past depth-indexing
(the whole point of this revision) removed the per-depth isolation that made capping safe under the
`Vault`-array shape. Concretely: if a live cap of N exists and one genuine restore is already live (anywhere
on the device, any depth), a coercer holding the phone can send N distinct-`attributeID` junk shards from
identities visible at their own depth and simply count how many `PendingShamirSecretRestore` rows exist
afterward — no key needed, no app-level acknowledgment needed, a raw row count on the physical device is
enough. Fewer new rows than junk shards sent means a live restore already existed before the coercer
started — which is close to the exact question this entire layering effort exists to keep unanswerable.
This is *sharper* than §3's original "denial channel" framing, which was about an attacker destroying a
real recovery's shares — this is a *counting* channel, revealing whether one exists at all, without
touching it. Filed as `bugs.md` Bug 122.

**The underlying tension, stated plainly, not resolved:** generalizing past depth (keying by the secret's
own identity, so non-BEK restores are representable at all) and preserving per-depth isolation (the
precondition §3 already requires for any cap to be safe) pull in opposite directions. A cap keyed by
`attributeID` has no isolation to fall back on; restoring isolation means partitioning by *the depth a
shard's sender was visible at on arrival* instead, which is close to reintroducing a depth field this
revision specifically removed to generalize in the first place, just relocated rather than eliminated.

**Decision, 2026-09-13: no cap, for now.** `PendingShamirSecretRestore` rows are genuinely unbounded —
`bugs.md` Bug 96 item 2 stays open, and is materially worse than before this revision (≈112 KB per junk
row instead of a few hundred bytes in the old `ReconstructShard`-based design). Deliberate, not an
oversight: the tension above needs its own resolution before any cap can be adopted safely, and shipping
one without resolving it would trade a resource-exhaustion bug for a duress-detection oracle, which is a
worse trade. Reseal-everything-on-every-write (Bug 120's fix for this container) is likewise not yet
adopted, pending the same open cost question a cap would have bounded.

**Resolved, same day, superseding "for now" above: no cap, permanently, not pending anything.** The tension
two paragraphs up *was* resolvable — a `depth` field scoped to arrival context (not to the secret's
identity) restores §3's isolation without giving up `attributeID`'s generalization, since the two answer
genuinely different questions and neither needs the other. Worked through and rejected anyway, for a reason
worth recording precisely because it isn't a security one: any cap needs a decision about what happens at
its boundary — reject silently, surface something, anything — which is real UX scope neither this document
nor `bugs.md` Bug 96 item 2's own "nice to have, not urgent" framing justifies taking on. So the resolution
to Bug 122 is not "we found the fix and deferred building it" — it's "no cap, ever, on this population,"
closing the counting oracle by removing the thing it depends on rather than by fixing it. Bug 96 item 2
stays open on the same permanent terms — see that entry's own 2026-09-13 note.

**A separate open question — whether this container needs `BackupEncryptionKey`/`VaultEntry`'s own
eager-filler-baseline treatment (Bugs 110/118) so row count doesn't reveal that the mechanism has ever been
used — raised and reconsidered the same day, leaning no.** The reasoning that made eager-fill necessary for
those two models doesn't transfer here. What eager-fill actually defends against is *depth-indexed* row
count: a coercer at depth 1 seeing 3 live `BackupEncryptionKey` rows learns there are at least 3 depths with
a configured backup deeper than what they've been shown — a direct count of hidden layers beneath the one
they're looking at. That is the fact worth hiding, not "a backup was ever configured," which is mundane on
its own. `PendingShamirSecretRestore` carries no depth information at all, live or orphaned — keying by
`attributeID` instead of depth was the whole point of this revision — so even a coercer who fully decrypts
every row learns only "a Shamir-shared secret was restored at some point," never which depth, never how
many depths, never whether any duress layer exists beneath the current one. And the action itself —
recovering a vault from trustee shares after losing a phone — is an ordinary, advertised feature unconnected
to duress; using it once doesn't imply Secure Mode is even configured. So the specific leak eager-fill was
built to close does not exist here, because the redesign that removed depth-indexing (generalizing past
BEK) also removed the thing that leak depended on. Left as a calmer footnote rather than a blocking
decision — nothing currently reads or writes this population, so nothing forces the question yet.

**Anti-pairings:**
- **Do not cap the restore shard buffer before the buffer is per-depth.** §3. Most likely to be picked
  up as obvious housekeeping by someone who hasn't read the reasoning — it introduces a cross-layer
  denial channel.
- **Do not pad the `.occbak` (Bug 100 r3) before item 5 above is decided.** If backup contents move
  into slots, that file stops existing. **Item 9 above proposes exactly that** — the file stops
  existing regardless of whether it's replaced by file-slots or by rows; either way, don't pad a file
  that's about to be retired.
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
| 96 (item 2) | Restore shard buffer unbounded | open, permanently accepted as of §6 item 9.3, 2026-09-13: each unbounded row now costs ≈112 KB (revised down from ≈215 KB, 2026-09-14, when Bug 124 removed the attestation field), not a few hundred bytes. A depth-scoped cap would have closed this safely (Bug 122's own resolution confirms the fix was viable) but was rejected for the UX scope it would require, not a technical blocker. No cap will be adopted. |
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

**Update, 2026-09-11 — §6 item 9 answers this independently of which of the two statements above was
the stale one.** Item 9 proposes retiring the pending-file side of this container entirely in favor
of rows, the same direction item 5's own successor took. Under that proposal there is no standalone
`.occbak` and nothing resembling a slot to tag either — the depth is which row it is. If item 9 is
adopted, this row's qualifier comes off regardless of how the §6-item-5-versus-this-row question
above would otherwise have resolved.

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

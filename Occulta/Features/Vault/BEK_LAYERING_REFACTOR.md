# BEK and Recovery — Layering Refactor

**Status:** design, not built. **Owner entry:** `Docs/Features/Secure Mode/bugs.md`, Bug 102.
**Compiled:** 2026-08-28, from the 2026-08-26/27 security review of `release/v1.10.3` and the
questions that followed it.

**What this is.** One place for the backup-encryption-key work: why the subsystem needs restructuring,
what the target looks like, how to build it, and every bug that led here or is expected to come out of
it. It does not replace `VAULT_BACKUP_GUIDE.md` (what the feature does) or `VAULT_SSS_GUIDE.md` (how
shards move) — it is the design record for changing both.

---

## 1. Why this is needed

**Recovery is device-wide in an app that is layered everywhere else.**

Contacts, vault entries, group membership, PIN gates and the layer arrays are all depth-partitioned.
The recovery subsystem is not: one BEK, one pending file, one shard buffer, plus a depth-0 privilege
bolted on so the real layer wins. The two layers therefore genuinely behave differently, and anything
a coercer can trigger and then watch becomes a way to read which layer he is in.

**The evidence is the shape of every fix so far.** Across 2026-08-26/27 the restore flow was patched
five times — uniform confirmation prompt, uniform banner, deleted acknowledgment, filler padding on
shard ops, shards moved out of a length-leaking file. Every one of those flattens a *symptom* of the
asymmetry. None removes it. Two were later found to have introduced a new tell while closing an old
one.

That is the signature of patching a structural problem at the surface. Make recovery per-layer and the
asymmetry stops existing, so the symptoms go with it instead of being suppressed one at a time.

### What is and is not layered today

| Thing | Scope | Consequence |
|---|---|---|
| Restored vault entries | **per depth** — `importBackup` stamps `visibleThroughDepth`, and entries are exact-match | contents are correctly contained |
| `BackupEncryptionKey` | one row, device-wide, no depth stamp | a restore completing in duress installs the device's real backup key |
| `shardMetadata` | inside the BEK payload, so device-wide | the trustee list is shared across layers |
| Pending `.occbak` | one file, device-wide | a restore armed in one layer blocks every other layer from arming |
| Restore shard buffer | `ReconstructShard` rows, no depth | shards cannot be attributed to a layer before reconstruction |
| Completion | depth 0 only | completes in one layer and not the other — a coercer-triggerable test |
| Shard *distribution* | no depth gate at all | **a duress layer can distribute shares of the real BEK — see §6.1** |

The contents are layered. The key and the machinery around it are not.

---

## 2. The target design

### 2.1 Shape

**One fixed-width array of fixed-count slots, one slot per depth.** Not several arrays, and not one
row per depth.

Each slot carries, as separately sealed fields:

| Field | Sealed under | Notes |
|---|---|---|
| BEK record | vault key | `bekBytes`, `distributionID`, `shardMetadata`, capped and padded |
| Collected restore shards | recovery buffer key | capped count — see §2.4 |
| Arming depth / state | recovery buffer key | written at arming, read at completion |

**Two keys do not force two containers.** Preserving a sealed blob never requires its key. A shard
arriving at a locked vault rewrites its slot's shard field and copies the BEK field's ciphertext
through untouched. One array is also fewer artifacts to pad, clean up and explain.

**Every sealed field's AAD must bind its slot index.** Without it, lifting slot 2's ciphertext into
slot 0 moves a duress layer's BEK into the real one. Same discipline `reconstructRowAAD` applies to
row ids and `backup-export-meta.dat` applies to its depth slots.

**Per-depth key derivation for the shard and state fields.** Derive the recovery buffer key with the
depth in the HKDF info, so code at depth 2 cannot open slot 0 — separation by cryptography rather than
by convention. The BEK field cannot get the same treatment cheaply, since the vault key is not
depth-derived and making it so touches every vault entry. State the asymmetry rather than implying
both halves are equally protected.

### 2.2 Where it lives

**`AppLayerConfig`** for the small per-depth scalars. It already holds fixed-width padded per-depth
arrays (`pinEnabledPerDepth`, the verifier arrays, the blob metadata arrays), is already classified in
`RotationRegistry`, and **already exists on every install** — `Manager.Security`'s constructor seeds
the row at first launch.

**A slotted file, sibling to `backup-export-meta.dat`,** for the bulk: the sealed backup contents and
the shard buffers. That file is already 32 fixed-width slots with constant length whatever the export
history holds; this is the same pattern, not a new idea. Keep it out of `AppLayerConfig` — that row is
read on essentially every security check and SwiftData loads the whole row, so megabytes of slots would
ride along with every `requireConfig()`.

**Eager creation is a constraint, not a detail.** The structure must exist, fully padded, from first
launch on every install — including ones that never configure Secure Mode and never run a restore.
`Manager.Security`'s constructor already applies this twice, to the config row and to the Secure Mode
SE key, and the SE-key argument is the sharper one: keychain items carry `kSecAttrCreationDate`, so
lazy creation leaks not just *whether* a PIN was configured but *when*. A recovery structure that
appears when backup is first set up reintroduces exactly that tell.

### 2.3 Shard attribution — the mechanism that makes per-layer work

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
which predicates on `deletionToken` alone. Adding it is the load-bearing piece of the whole design, and
it has scope beyond shards — see §6.4.

### 2.4 Caps, and why they are only safe here

Fixed width implies a cap on shards per depth. That closes Bug 96 item 2's unbounded growth for free.

**A cap on a *shared* buffer would be a cross-layer denial channel** — an attacker fills it with junk
and evicts a real recovery's shards. The cap is safe only once the buffer is per-depth. Do not add one
before then.

---

## 3. Build stages

Each stage is independently shippable; 1 and 2 carry most of the risk.

| # | Stage | Verify |
|---|---|---|
| 1 | Slotted BEK array in the sibling file, seeded with filler at first launch. Migrate the single `BackupEncryptionKey` row into slot 0 | array length identical whether 0 or 32 depths hold a BEK; `RotationRegistryTests` passes; existing export/import tests pass against slot 0 |
| 2 | Route BEK access by depth — `fetchDecodedBEK`, `setupBEK`, `currentBEK`, `bekSetupState`, `bekShardMetadata`, `exportBackup`, `reconstructBEK` | a BEK created at depth 2 is invisible at depth 0 and vice versa |
| 3 | Sender-visibility gate on inbound processing (§2.3), with the drop/defer decision from §6.4 | a shard from a contact hidden at the current depth is not banked; a trustee's retry lands when the user returns to their depth |
| 4 | Per-depth restore state: arming, sealed backup contents, shard buffer, per-depth cancel | arming in duress does not block depth 0; cancel clears only its own layer |
| 5 | Completion per layer; remove the depth-0 privilege | a restore armed at depth N completes at N and nowhere else; entries land visible only at N |
| 6 | Restore the truthful acknowledgment — each layer answers about its own slot | at every depth the reply is that layer's truth and matches what a real session there produces |

**Acceptance criterion for the whole thing:** a coercer can arm, set up his own trustees, collect and
complete a restore in his layer, and see exactly what a working app does — because it *is* a working
app in that layer, not a simulation of one. That is the test that distinguishes this from the
flattening it replaces.

**A large change for a patch release.** It touches BEK storage, restore, export, shard distribution
and the vault UI, with migrations. This originally read "not a patch-release change — own branch off
`develop`, minor version"; both halves were overridden on 2026-08-28. It ships in **v1.10.3**, on
`v1.10.3/bek-layering-refactor` off `release/v1.10.3`. Reasoning, and what the patch framing costs,
in §7.

---

## 4. Open decisions — settle before stage 1

1. **Per-depth shard distribution.** Does each layer carry its own trustee set? May a duress layer
   distribute at all? What does a trustee see when holding shards for two of the owner's layers? This
   shapes the slot record, so it cannot be deferred.
2. **Slot size cap for backup contents.** Fixed slots cap vault backup size. Pick the cap and enforce
   it at **export**, with a clear failure — not at restore, when the user has no vault left.
3. **Drop versus defer for non-shard payloads** behind the §2.3 gate. Shards retry; messages do not.
   Deferring means storing the bundle, which is a cross-layer container again unless slotted.
4. **The `storePendingRestore` tombstone soft spot** — §7.3. A downgraded build can still *arm* a
   restore against a tombstoned row, because that one site uses `try?` where its siblings use `try`.
   Accept it, or add a guard distinguishing "no row" from "row present, undecryptable."

---

## 5. Bugs — past

Everything that led here. Full reasoning lives in `Docs/Features/Secure Mode/bugs.md`.

| Bug | What | Status |
|---|---|---|
| 88 | Backup ignored `visibleThroughDepth` in both directions | fixed — export and import are depth-scoped |
| 93 | Vault recovery was depth-blind in state, UI and trigger | fixed; its harm-4 follow-up is partly reverted by this refactor |
| 94 | Restore path trusted attacker-supplied material | all three remedies in — overwrite refusal, trustee attestation, confirmation |
| 94a | Remedy 2's attestation field unpadded — slot size named the trustee mid-recovery | fixed — every op ships an attestation, real or filler |
| 96 (item 1) | Two traps on decoded content | fixed |
| 96 (item 2) | Restore shard buffer unbounded | open — cap falls out of §2.4 |
| 96 (item 3) | Export plaintext left unzeroed | open |
| 99 | A coercer supplying his own trustees can test for duress | open — subsumed here except the pending-file tag |
| 100 r1 | Restore artifacts not excluded from device backups | fixed 2026-08-27 |
| 100 r2 | Shard file length was a keyless progress counter | fixed — rows; superseded by §2.1 slots |
| 100 r3 | `.occbak` length estimates vault size | open — moot if §2.2 slots the contents |
| 101 | `Documents/Inbox` copies retained and backed up | open — needs a device check |
| 102 | The BEK has no layer concept | **this document** |
| 105 | A duress layer can distribute shares of the real BEK | open — §6.1 |

**Adjacent, not BEK, but same root cause** — views and inbound paths that ignore depth: Bug 103
(reader renders a hidden contact's name, phone, email) and Bug 104 (inbound identity challenge renders
a hidden contact's name). Both are instances of "the depth dimension was not applied at the view
layer," and §2.3's gate is the server-side half of the same problem.

---

## 6. Bugs — expected, and traps to avoid

### 6.1 A duress layer can distribute shares of the real BEK today — Bug 105

**Filed as Bug 105**, 2026-08-28, found while scoping this document. Full entry and remedy options in
`Docs/Features/Secure Mode/bugs.md`; summarised here because it is the sharpest evidence for §1.

`prepareBEKShards` has no depth gate — it reads the one device-wide BEK via `fetchDecodedBEK`, and
`Vault+ShardSetup.swift` contains zero references to `currentDepth` or `isVisible`. The trustee
*picker* is correctly filtered (`mlkemEligibleContacts` applies `isVisible(atDepth:)`), which is
exactly what makes this easy to miss: the contacts are per-layer, the key they are handed shares of is
not.

So at a duress depth, through ordinary UI and with no attacker-supplied file and no shard delivery, a
coercer can distribute shares of the owner's **real** backup key to his own phones. Two harms:

- He holds threshold shares of the real BEK. Latent until he obtains any `.occbak` — via a device
  backup, iCloud, or Bug 101's `Documents/Inbox` copy.
- Immediate: `prepareBEKShards` reuses the existing `distributionID` and **overwrites**
  `shardMetadata`, so the owner's real trustee list is replaced by his. Genuine trustees still hold
  valid shares, but the device's record of who holds what is gone, `bekSetupState` reports his set, and
  shard health shows his phones.

This is the cleanest demonstration of the thesis in §1, because every step is legitimate app
behaviour. It also answers open decision §4.1 empirically: a duress layer can distribute today, and it
distributes the real key.

**Its short-term remedy is genuinely unattractive**, which is an argument for the refactor rather than
against fixing it now: refusing distribution above depth 0 closes the harm but adds an observable
difference between layers — the trap two fixes already fell into this week. Bug 105 records both
options rather than picking the smaller diff.

### 6.2 Anti-pairings

**Do not cap the restore shard buffer before the buffer is per-depth.** §2.4. This is the item most
likely to be picked up as obvious housekeeping by someone who has not read the reasoning, and it
introduces a cross-layer denial channel.

**Do not pad the `.occbak` (Bug 100 r3) before §2.2 is decided.** If backup contents move into slots,
that file stops existing.

**Do not ship Bug 100 r1 alone.** It excludes the measurement while Bug 101 leaves the content
unsealed in `Documents/Inbox`. One device session verifies both.

### 6.3 Regressions this refactor must not introduce

- **Slot count must never vary.** N occupied slots readable as N layers, by count or by length,
  reintroduces the leak the padding exists to close.
- **Nothing may be created lazily.** §2.2. An artifact that appears when a feature is first used is a
  tell regardless of how well its contents are sealed.
- **Deferral must not be silently dropped.** Until stage 5 lands, `attemptBEKRestore`'s depth guard is
  the only thing preventing a duress session from completing a depth-0-armed restore. The guard changes
  shape rather than disappearing.
- **No new depth-conditional UI.** Every prompt, banner and acknowledgment must read identically across
  layers unless the underlying state is genuinely per-layer. Two fixes in this area were themselves
  found to be new oracles — a confirmation shown only at depth 0, and a banner absent above it.

### 6.4 Known scope creep

The §2.3 gate applies to inbound processing generally, not to shards. Shards are the only payload with
a retry guarantee, so messages and prekeys need their own answer. Expect this stage to grow, and do not
let it be absorbed silently into stage 3.

### 6.5 Tripwire

`VaultEntryType` has `document` and `photo` **commented out**. The whole fixed-slot design rests on a
vault backup being kilobytes. Enabling either makes the vault bulk data and invalidates §2.1 entirely.
That enum is the place to notice, so the constraint belongs as a comment there too.

---

## 7. Migration and release scope

Settled 2026-08-28. Records three decisions and the alternatives rejected to reach them.

### 7.1 Release scope

Ships in **v1.10.3**, branch `v1.10.3/bek-layering-refactor` off `release/v1.10.3`.

§3's original "own branch off `develop`" was stale on its own terms: `develop` is **133 commits behind
`release/v1.10.3` and zero ahead**. Branching there would have dropped every fix this refactor builds
on — Bug 100 r1, Bug 94a's attestation padding, and the Bug 105 filing itself.

The patch framing is a deliberate trade, not an oversight. Bug 105 is live, and its standalone remedy
is the unattractive one §6.1 describes — refusing distribution above depth 0 closes the harm and opens
a new observable difference between layers. Shipping the refactor instead of a patch that adds a tell
is the better of two imperfect options. What it costs is stated in §7.2: a patch version implies
downgrade is safe, and after this migration it is not.

### 7.2 Compatibility — what is achievable and what is not

Two directions, and they have opposite answers.

**New build reads old data — free, and required regardless.** `BackupEncryptionKey.Payload` is a
`Codable` struct sealed under the vault key; fields added as optional decode against existing
ciphertext untouched.

**Old build reads what the new build wrote — impossible for slot 0, by construction.** An old build
keeps working only if the device-wide `BackupEncryptionKey` row still holds the real key. That row
*is* Bug 105: `prepareBEKShards` reaches it through `fetchDecodedBEK`, which does `fetch(...).first`
with no depth check (`Vault+Manager+Backup.swift:986`). Preserving it for downgrade preserves the
exact artifact this refactor exists to remove. The two goals are one variable in opposite directions —
no design resolves them.

The conflict is narrower than it first looks. It is **only slot 0's BEK bytes**. Everything else is
additive and downgrade-tolerant:

| Piece | Old build's view | Verdict |
|---|---|---|
| Sibling slot file (depths ≥1, shard buffers, restore state) | never heard of it, ignores it | duress-layer state *unavailable*, not lost; re-upgrading restores it |
| §2.3 visibility gate, §2.4 cap | behavioral, no persisted format | downgrade loses the gate, nothing else |
| Slot 0's BEK | the thing that must stop being device-wide | **breaks — see §7.3** |

**Add a `formatVersion` byte to the new file's sealed plaintext.** `ExportMetaSlotCodec` has none
(`Vault+Manager+Backup.swift:815`) — a gap worth not repeating. This also argues for §2.2's
file-based choice more strongly than §2.2 itself does: the project has **no
`VersionedSchema`/`SchemaMigrationPlan` at all**, an absence already blocking the `GlobalShardConfig`
removal (`RotationRegistry.swift:70`) and flagged again in `PQmigration.swift:308`. A file sidesteps
the missing migration plan; a new `@Model` would sit on top of lightweight migration and hope.

### 7.3 Tombstone the legacy row — do not delete it

When slot 0's BEK moves into the slot file, keep the `BackupEncryptionKey` row and overwrite
`encryptedPayload` with **same-length filler**.

Deleting the row is itself a new tell — "this device once had a BEK and no longer does." A
filler-filled row is indistinguishable from a real one on cold disk, which satisfies §2.2's
eager-creation rule instead of fighting it.

More importantly, a downgraded build then **fails closed at three of four sites**:

| Site | Behavior on a filler row | Why it matters |
|---|---|---|
| `setupBEK()` (`:108`) | guards on `existing.isEmpty` — row *presence*, not decryptability — so it no-ops | blocks the real harm: minting a fresh BEK with a new `distributionID`, silently invalidating the genuine trustee distribution (Bug 105's second harm, arrived at from the other direction) |
| `currentBEK()` (`:133`) | throws | no export under a wrong key |
| `reconstructBEK` (`:494`) | uses `try`, not `try?` — decrypt failure propagates | reconstruction refuses |
| `storePendingRestore` (`:703`) | uses `try?`, so `alreadyHasBEK` reads false | **soft spot** — a downgraded build still lets you *arm*. Arming, not completing; recoverable, but handle it deliberately rather than discover it |

Net: downgrade degrades to *fails closed and says so*, rather than *works fine* or *silently destroys
the distribution*. That is the honest ceiling, and it is what §7.1's patch framing actually buys.

### 7.4 In-flight restores — adopt, do not dual-run

A restore waits on trustees delivering shards in person, so it can sit armed for **days**. Losing that
on update is a real harm, and the update must not cause it.

**The destination is unambiguous.** A legacy in-flight restore is depth-0-destined by construction —
`attemptBEKRestore` guards `currentDepth == 0` (`:741`). §2.3's attribution problem does not arise:
no legacy restore can have been destined for anywhere else. So the in-flight state is **adopted into
slot 0** and finished by the new mechanism. The old path is not kept alive to finish it.

| Legacy state | Adopted as | Note |
|---|---|---|
| pending `.occbak` | slot 0's sealed backup contents | straight lift |
| `ReconstructShard` rows | slot 0's shard buffer | **needs re-sealing** — sealed under `deriveRecoveryBufferKey()`, which is not depth-derived today (`ReconstructShard+Model.swift:52`) while §2.1 requires depth in the HKDF info |
| completion at depth 0 | completion at slot 0 | same behavior, one path |

The re-seal is the only step that is not a copy, and it needs the vault unlocked — so **adoption runs
at the first depth-0 unlock after update, not at launch**.

**Adopt the banked shards as-is; do not re-validate them against §2.3's gate.** They were banked
before the gate existed, but they were depth-0-destined anyway and Bug 94 remedy 2's per-sender
attestation already applied when they were banked. Re-validating could drop a shard from a trustee
since hidden, delaying exactly the restore this is meant to protect.

**Fallback:** if adoption cannot complete cleanly — vault key unavailable, malformed rows — refuse and
tell the user to **re-arm**. Never fall back to the old rules. Re-arming is a visible one-time cost
that reads identically at every depth; silently running the legacy path is not.

### 7.5 Rejected alternatives

**Dual-run: legacy restores finish under legacy rules, new arms use the new mechanism.** Rejected on
three counts, worst first:

- **The rule set becomes attacker-selectable, and attacker-pinnable.** A coercer who arms before
  updating keeps every pre-refactor weakness on a patched device: no §2.3 gate, uncapped buffer
  (Bug 96 item 2), depth-0 completion privilege. A downgrade attack in time rather than in version.
- **Two mechanisms are two completion paths.** §6.3 notes `attemptBEKRestore`'s depth guard is the
  only thing preventing a duress session from completing a depth-0-armed restore until stage 5.
  Dual-running requires that guard to stay correct in two places that can disagree — and two fixes
  this month each closed one tell while opening another.
- **It is observable.** Legacy leaves a pending `.occbak` on disk; the new path has slotted contents.
  Different artifacts, different timing. A coercer who can arm and watch learns which path he is on,
  a proxy for device history, and a new conditional where §6.3 wants none.

**Complete-then-migrate: defer the whole migration until any in-flight restore finishes.** Strictly
worse than dual-run. Migration is gated on an event that may never happen, and arming is something a
coercer can do (Bug 99) — so **he can pin the device on the vulnerable design indefinitely** by
keeping a restore armed.

**Keep depth 0's BEK in the legacy row, slot only depths ≥1.** This is the one option that delivers
genuine downgrade safety, and it is still wrong: the row's presence then means *"depth 0 has a BEK"*
while the file means *"some other depth does"* — two artifacts of different shapes, which is §6.3's
"slot count must never vary" leak wearing a different hat.

### 7.6 Consequences for the stage plan

- Stage 1 gains the tombstone (§7.3) and the `formatVersion` byte (§7.2).
- Stage 1 gains an adoption step (§7.4) that runs at first depth-0 unlock, with its own verify: a
  restore armed on the prior build, with shards banked, completes after update without re-arming.
- §4 gains a fourth open decision: **the `storePendingRestore` soft spot in §7.3** — whether a
  downgraded build arming a restore against a tombstoned row is acceptable, or wants a guard that
  distinguishes "no row" from "row present, undecryptable."

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

**This is Bug 92's subject, and it has a remedy.** The vault key opens every slot, so the BEK field is
separated by convention: only the code declining to read slot 0 at depth 2 keeps them apart, and a
device dump yields all of them regardless. Bug 92 identifies the one input a coerced session does not
hold — the PIN, which is knowledge rather than stored material — and proposes
`fileKey = HKDF(BEK ‖ slowKDF(PIN, salt))`. Adopting that here would make the separation
cryptographic. **Open decision, see §4.4**, and note it carries a hard dependency: no slow KDF exists
in the codebase, and a PIN-derived key without one is a design that looks layered and is not.

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

**Not a patch-release change.** It touches BEK storage, restore, export, shard distribution and the
vault UI, with migrations. Own branch off `develop`, minor version.

---

## 4. Open decisions — settle before stage 1

1. **Per-depth shard distribution.** Does each layer carry its own trustee set? May a duress layer
   distribute at all? What does a trustee see when holding shards for two of the owner's layers? This
   shapes the slot record, so it cannot be deferred.
2. **Slot size cap for backup contents.** Fixed slots cap vault backup size. Pick the cap and enforce
   it at **export**, with a clear failure — not at restore, when the user has no vault left.
3. **Drop versus defer for non-shard payloads** behind the §2.3 gate. Shards retry; messages do not.
   Deferring means storing the bundle, which is a cross-layer container again unless slotted.
4. **Convention or cryptography for the BEK field's slot separation** (§2.1, Bug 92). Adopting
   PIN-combined derivation requires first adding a slow KDF, and changes the recovery contract —
   shards alone stop being sufficient, and PIN rotation orphans old backup files. Accepting
   convention is defensible; accepting it silently is not.

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
| 92 | A backup file is readable from any layer (offline half) | open — complementary, see §2.1 |
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

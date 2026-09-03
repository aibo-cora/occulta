# Storage Layering — Vault, Recovery, and the BEK

**Status:** design, not built. Some sub-decisions settled; most open. **Owner entries:**
`Docs/Features/Secure Mode/bugs.md` Bug 102 (BEK), and `forensic-trace-avoidance.md` S5 (contacts),
S8 (vault entries). **Compiled:** 2026-09-02, consolidating `BEK_LAYERING_REFACTOR.md` (compiled
2026-08-28) and `AT_REST_LAYERING.md` (compiled 2026-09-02) — both now redirect stubs pointing here.
The two were split by which file first raised the topic, not by any real boundary in the design; every
session since has had them referencing each other's findings. This is the one place for that material.

**What this is.** Why the storage layer needs restructuring, what the target looks like, how to build
it, every bug that led here or is expected out of it, and every open decision — for contacts (S5),
vault entries (S8), the BEK, and the recovery machinery around it, together, because they share a
mechanism and in one case share an actual container. Does not replace `VAULT_BACKUP_GUIDE.md` (what
the feature does) or `VAULT_SSS_GUIDE.md` (how shards move) — this is the design record for changing
both, plus the parallel work on contacts.

---

## 1. Why this is needed

**Recovery is device-wide, and so is most other sensitive storage, in an app that layers
*classification* almost everywhere else.**

Contacts, vault entries, group membership, PIN gates, and the layer arrays are all depth-partitioned
at the classification level — a `visibleThroughDepth` stamp gates what's shown. But the underlying
*storage* mostly isn't: one `BackupEncryptionKey` row, one pending-restore file, one shard buffer, a
depth-0 completion privilege bolted on top for recovery; live SQLite rows with plaintext row counts
and timestamps for both sensitive contacts (S5) and vault entries (S8). The classification layer says
what a session may see; underneath it, in every one of these cases, the same bytes and the same row
counts are sitting there for anyone who reaches the raw storage.

**The evidence is the shape of every fix so far.** Across 2026-08-26/27 the restore flow alone was
patched five times — uniform confirmation prompt, uniform banner, deleted acknowledgment, filler
padding on shard ops, shards moved out of a length-leaking file. Every one of those flattens a
*symptom* of the classification/storage mismatch. None removes it. Two were later found to have
introduced a new tell while closing an old one — the signature of patching a structural problem at
the surface.

That matters for sequencing as much as for design: per-layer recovery, or a per-layer vault, built on
storage that isn't itself layered inherits the exact gap it's trying to close.

---

## 2. What is and is not layered today

| Thing | Scope | Consequence |
|---|---|---|
| Sensitive contacts (S5) | `visibleThroughDepth` + UI filter classify; rows stay live, readable under the canonical DB key | a raw SQLite read on an unlocked device sees every sensitive contact regardless of depth |
| Vault entries (S8) | `visibleThroughDepth` (exact-match) classifies, stamped at activation Step 8; `id`/`createdAt` are plaintext columns | row count and creation timestamps are identical at every depth — not depth-gated at all |
| Restored vault entries | **per depth** — `importBackup` stamps `visibleThroughDepth`, exact-match | contents are correctly contained (this part already works) |
| `BackupEncryptionKey` | one row, device-wide, no depth stamp | a restore completing in duress installs the device's real backup key |
| `shardMetadata` | inside the BEK payload, so device-wide | the trustee list is shared across layers |
| Pending `.occbak` | one file, device-wide | a restore armed in one layer blocks every other layer from arming |
| Restore shard buffer | `ReconstructShard` rows, no depth | shards cannot be attributed to a layer before reconstruction |
| Completion | depth 0 only | completes in one layer and not the other — a coercer-triggerable test |
| Shard *distribution* | no depth gate at all | **a duress layer can distribute shares of the real BEK — see §9** |

The pattern repeats at every scale: contents are layered, the container holding them is not.

---

## 3. What already exists — and it is most of the mechanism

`LayerStore` (`SecureMode+LayerStore.swift`, `LayerStore.md`) is already a per-depth fixed-width
container, shipped, currently holding sensitive contacts:

- **32 slots**, tied to `AppLayerConfig.maxVerifierCount` so file size and verifier-array length leak
  no more than each other. One slot per activation layer, assigned via `sealedBlobSlots`.
- **`slotPlaintextSize = 32 KB`, fixed.** Every slot — real payload or random filler — seals to
  exactly that length, so the file is always `32 × (32 KB + 28)` bytes regardless of contents.
- **Eagerly created**, from first launch, before Secure Mode is ever configured. No header, no magic
  bytes, no version field, no slot count. Indistinguishable from a vault backup.
- **Full regeneration on every write** — all 32 slots re-sealed with fresh nonces, so padding slots
  cannot be identified by diffing two versions of the file.
- **Capacity is already enforced and already surfaced.** `push` throws `.payloadTooLarge` before any
  I/O, and `estimatedSize(for:)` drives a live capacity indicator in the contact classification UI
  (`SecureModeSetupFlow`) — the user sees the budget as they spend it rather than hitting a wall at
  commit time.

That last point answers "we should not impose caps, we need graceful flexibility" directly. A fixed
envelope is not negotiable — it's what makes an occupied slot indistinguishable from an empty one.
What *is* negotiable is whether the user can see the budget as they spend it. This codebase already
chose "yes" for contacts; that's the pattern to copy for every new cap decision below, not a per-entry
byte limit discovered only at export or distribute time.

**What `LayerStore` deliberately does not hold:** vault per-entry keys, prekeys, or `CustodyShard`
records — see §4 for why the first of those is load-bearing, not incidental.

---

## 4. The protection domains

`LayerStore.md` excludes vault per-entry keys deliberately: *"Storing them would widen the attack
surface since a store compromise requires only the SE Secure Mode key, bypassing the biometric gate
that otherwise protects vault content (Bug 8)."* Verified directly in `Key+Manager.swift` rather than
taken from prose — there are three domains, not two, and one of them cuts across the BEK/vault line in
a way worth building around rather than working past:

| Key | Derived by | Biometric gate | Seals today |
|---|---|---|---|
| Secure-Mode key | (existing) | No | Contact `LayerStore`, local DB key |
| **Vault key** | `deriveVaultKey(context: LAContext)` | **Yes** | Vault entry content (`VaultManager.currentKey()` calls this directly) — **and, per §5.1's own table, the BEK record itself** |
| Recovery buffer / shard custody key | `deriveRecoveryBufferKey()` — no `LAContext` parameter | **No** | `CustodyShard` rows, the shard buffer, restore/arming state |

**Putting vault entries into the existing Secure-Mode-keyed store would collapse domains 1 and 2 and
strictly downgrade vault protection.** It's also why S8 is rated below S5: a duress-PIN-only coercer
cannot open the vault at all, so the row-count tell needs duress PIN *and* forced biometrics to be
reachable — see §4a for why that bar may be lower than it looks for this app's actual threat model.

**But the BEK record is already vault-key-sealed** — the same gate as vault entry content, not the
same gate as the shard buffer sitting beside it in the design below. The shard buffer and
restore/arming state are recovery-buffer-key-sealed deliberately, and must stay that way: shards
arrive over ordinary messaging, asynchronously, and gating their receipt behind a Face ID prompt would
be a real UX regression, not just a stricter default.

**Not only a cold-disk risk.** A coercer who compels biometric auth causes `deriveVaultKey` to hand
the derived `SymmetricKey` to the app process, in ordinary memory, for the duration it's used.
Extracting it from there needs forensic tooling — jailbreak plus debugger, or GrayKey/Cellebrite-class
extraction — not a break of the Enclave itself; the private key never leaves it. But this project's
own threat model already assumes exactly that capability for the local DB key
(`forensic-trace-avoidance.md` S1). With the vault key alone, a coercer at depth 2 could in principle
decrypt every other slot's BEK record, including `shardMetadata` — trustee counts and identities — at
depths they were never meant to see.

**Consequence for the whole design:** one mechanism, applied twice, split by key domain rather than by
feature —
- **Vault-key-gated:** sensitive vault entries (if built, §6) + the BEK record — same gate, natural
  co-tenants of one `LayerStore`-shaped file.
- **Recovery-buffer-key-gated:** the shard buffer + restore/arming state (+ `CustodyShard`, §8) — a
  second, separate `LayerStore`-shaped file, kept unlockable without biometrics on purpose.

The exported `.occbak` backup joins neither. Its contents are sealed under the **BEK itself**, not the
vault key — necessarily, since a backup must open on a brand-new device that reconstructed the BEK
from Shamir shares and has no biometric enrollment history for this install at all. The vault key is
device-bound; the BEK is the thing designed to survive the device being gone. One exists to protect
the device you still have, the other to survive losing it — they cannot share a key without breaking
one of those two purposes.

### 4a. Is "duress PIN + forced biometrics" actually the high bar S8 assumes? — unverified claim, not a finding

Raised as a question, not settled here. S8's downgrade rests on that compound attack being harder than
PIN coercion alone. The counter-argument — that biometric unlock is compellable under a lower legal bar
than a memorized PIN in some jurisdictions, so the compound attack may be closer to the default
coercion pattern than a stacked edge case for this app's stated threat model — is a **legal claim**,
not a technical one, and has not been checked against actual counsel or jurisdiction-specific sourcing.
Route it through the same counsel pass `Docs/Audit/OPEN_LIMITATIONS.md` Section E already queues for
duress/coercer language; don't treat it as established reasoning on the strength of sounding plausible.
What *is* verified, independent of this claim: the failure mode itself — the UI showing "No entries
yet" while the raw DB holds N rows — is real regardless of how the legal question resolves. The claim
only affects *how urgent* S8 is rated, not whether it exists.

---

## 5. Target design

### 5.1 Shape

**One fixed-width array of fixed-count slots per container, one slot per depth.** Not several arrays,
not one row per depth. Two containers per §4, not one and not three:

**Vault-key-gated container** — vault entries (if built, §6) + BEK record, as separately sealed
fields:

| Field | Notes |
|---|---|
| BEK record | `bekBytes`, `distributionID`, `shardMetadata` — capped and padded, see §8 |
| Sensitive vault entries (if built) | canonical copy; DB rows become unreadable shells |

**Recovery-buffer-key-gated container** — shard machinery, as separately sealed fields:

| Field | Notes |
|---|---|
| Collected restore shards | capped count — see §5.4 |
| Arming depth / state | written at arming, read at completion |
| `CustodyShard` (candidate) | duress-mode accessibility still an open decision, §8 |

**Two record types per container do not force two containers.** Preserving a sealed field never
requires its own key to preserve — a shard arriving at a locked vault rewrites its own field and
copies untouched fields' ciphertext straight through. One array per key domain is also fewer artifacts
to pad, clean up, and explain than one per feature.

**Every sealed field's AAD must bind its slot index.** Without it, lifting slot 2's ciphertext into
slot 0 moves a duress layer's BEK — or a duress layer's vault entries — into the real one. Same
discipline `reconstructRowAAD` applies to row ids and `backup-export-meta.dat` applies to its depth
slots.

**Per-depth key derivation for the recovery-buffer container.** Derive the recovery buffer key with
the depth in the HKDF info, so code at depth 2 cannot open slot 0 — separation by cryptography rather
than convention. **The vault-key-gated container cannot get the same treatment for free** — the vault
key is not depth-derived, and making it so touches every vault entry. State the asymmetry rather than
implying both containers are equally protected; §8 has the remedy and its two applications.

### 5.2 Where it lives

**`AppLayerConfig`** for genuinely small per-depth scalars only — it already holds fixed-width padded
per-depth arrays (`pinEnabledPerDepth`, the verifier arrays, the blob metadata arrays), is already
classified in `RotationRegistry`, and already exists on every install (`Manager.Security`'s
constructor seeds the row at first launch). Not a fit for either container above — both carry bulk
payloads, and that row is read on essentially every security check; SwiftData loads the whole row, so
megabytes of slots would ride along with every `requireConfig()`.

**Two `LayerStore`-shaped files, siblings to `backup-export-meta.dat` and to each other** — one per
key domain from §4. That file is already 32 fixed-width slots with constant length whatever the export
history holds; this is the same pattern, not a new idea, applied twice.

**Eager creation is a constraint, not a detail, for both.** Each structure must exist, fully padded,
from first launch on every install — including ones that never configure Secure Mode and never run a
restore. `Manager.Security`'s constructor already applies this twice, to the config row and to the
Secure Mode SE key, and the SE-key case is the sharper precedent: keychain items carry
`kSecAttrCreationDate`, so lazy creation leaks not just *whether* something was configured but *when*.
A recovery or vault-concealment structure that appears when first used reintroduces exactly that tell.

### 5.3 Shard attribution — the mechanism that makes per-layer work

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
which predicates on `deletionToken` alone. Adding it is the load-bearing piece of the whole design,
and it has scope beyond shards — see §10.4.

### 5.4 Caps, and why they are only safe here

Fixed width implies a cap on shards per depth. That closes Bug 96 item 2's unbounded growth for free.

**A cap on a *shared* buffer would be a cross-layer denial channel** — an attacker fills it with junk
and evicts a real recovery's shards. The cap is safe only once the buffer is per-depth. Do not add one
before then. Same principle applies to every other cap named in §8 — pad and cap only once the field
being capped is already per-depth, never before.

---

## 6. Candidates and decisions — contacts (S5) and vault entries (S8)

**Contacts (S5) — build, first.** Design B is already specified and deferred: sensitive contacts
become unreadable shells in the DB, the existing contact `LayerStore` blob is the sole readable copy,
loaded into memory on normal unlock and wiped on lock. No new file, no new key — four named steps.
Pilots the lifecycle vault entries need, on infrastructure that already ships.

**Vault entries (S8) — build, via candidate 3.** Three candidates were weighed; the decision is
recorded, not the rejected ones deleted:
1. ~~Leave as-is; re-accept the gap explicitly.~~
2. ~~Decoy row padding~~ — S8 itself already called this "complexity without a strong attacker model."
3. **Chosen.** A vault-key-gated `LayerStore` instance, holding sensitive entries as the canonical
   copy — and, per §4/§5.1, a natural host for the BEK record too, since both already answer to the
   same key.

**Decided by the release owner, 2026-09-02:** build both, S5 before S8. The risky, unproven part of
candidate 3 isn't the file mechanism (`LayerStore` already ships) — it's the "unreadable shell in the
DB, canonical copy in the sealed file, loaded to memory on unlock, wiped on lock, merged with live rows
in the UI" lifecycle, which has never been built anywhere in this codebase. Contacts' Design B is that
exact pattern, already specified, needs no new container or key, and has sat deferred. Piloting the
lifecycle on S5 first, rather than making the vault the first real test of an unproven pattern, is the
agreed order. §4a stayed unverified throughout and was not the basis for this decision.

---

## 7. Build stages

Contacts and vault entries (§6) and the BEK/recovery machinery (below) are independently buildable —
neither blocks the other, though the vault-key-gated container's final shape (§5.1) is shared, so it's
worth building it once, sized for the BEK record alone first (see §9's narrower Bug 105 scope), and
widening it when S8 lands rather than redoing it.

**BEK/recovery stages** — each independently shippable; 1 and 2 carry most of the risk and are the
entire scope needed to close Bug 105 (§9):

| # | Stage | Verify |
|---|---|---|
| 1 | Slotted BEK array in the vault-key-gated file, seeded with filler at first launch. Migrate the single `BackupEncryptionKey` row into slot 0 | array length identical whether 0 or 32 depths hold a BEK; `RotationRegistryTests` passes; existing export/import tests pass against slot 0 |
| 2 | Route BEK access by depth — `fetchDecodedBEK`, `setupBEK`, `currentBEK`, `bekSetupState`, `bekShardMetadata`, `exportBackup`, `reconstructBEK` | a BEK created at depth 2 is invisible at depth 0 and vice versa |
| 3 | Sender-visibility gate on inbound processing (§5.3), with the drop/defer decision from §10.4 | a shard from a contact hidden at the current depth is not banked; a trustee's retry lands when the user returns to their depth |
| 4 | Per-depth restore state: arming, sealed backup contents, shard buffer, per-depth cancel | arming in duress does not block depth 0; cancel clears only its own layer |
| 5 | Completion per layer; remove the depth-0 privilege | a restore armed at depth N completes at N and nowhere else; entries land visible only at N |
| 6 | Restore the truthful acknowledgment — each layer answers about its own slot | at every depth the reply is that layer's truth and matches what a real session there produces |

**Acceptance criterion for the whole thing:** a coercer can arm, set up his own trustees, collect and
complete a restore in his layer, and see exactly what a working app does — because it *is* a working
app in that layer, not a simulation of one. That is the test that distinguishes this from the
flattening it replaces.

**A large change for a patch release.** It touches BEK storage, restore, export, shard distribution
and the vault UI, with migrations. Ships in **v1.10.3**, on `v1.10.3/bek-layering-refactor` off
`release/v1.10.3` — reasoning, and what that costs, in §11.

---

## 8. Open decisions

Reorganized by which container each belongs to, since that's what determines whether it's blocked on
anything else here.

### Vault-key-gated container (entries + BEK record)

1. **Per-depth shard distribution — settled 2026-09-02.** Does each layer carry its own trustee set?
   May a duress layer distribute at all? What does a trustee see when holding shards for two of the
   owner's layers? Resolved without new design — each sub-question falls out of §5.1 and §10.3 plus
   the trustee data model already in place:
   - **Own trustee set per layer: yes, for free.** `shardMetadata` already lives inside the BEK
     payload; once the BEK is slotted per depth, `shardMetadata` becomes per-depth automatically. The
     contact picker feeding `prepareBEKShards(threshold:recipients:)` (`Vault+Manager+Backup.swift:368`)
     already filters by `isVisible(atDepth:)`. The only thing that was ever device-wide was the key
     itself — Bug 105's exact finding.
   - **Duress-layer distribution: allowed uniformly at every depth, never gated to depth 0.** Refusing
     it above depth 0 is exactly the depth-conditional behavior §10.3 forbids, and is the same trap two
     other fixes fell into the same week. Once the BEK is depth-scoped, distributing at depth N
     distributes depth N's own decoy key — nothing left to leak, so refusal buys no security and only
     adds a tell.
   - **Same trustee holding shards for two layers: already handled, nothing depth-aware needed on the
     trustee side.** `visibleThroughDepth` is a ceiling (`value >= depth`), so one contact visible at
     both depth 0 and depth 2 is the normal case, not an edge case. `CustodyShard`
     (`CustodyShard+Model.swift`) stores shards keyed by an opaque row id with no contact or generation
     linkage in plaintext, and already tolerates multiple live shards from one owner — old PEK
     rotations sit inert beside current ones. A trustee designated at both depths just accumulates two
     rows, indistinguishable from two ordinary rotations. The trustee's device should never need to
     know the owner uses depths at all.
   Net: nothing new to build for this decision specifically — a consequence of §5.1 + §10.3 + the
   existing trustee model, not a separate mechanism.

2. **The container's overall slot budget.** Two payload types now compete for it (vault entries, BEK
   record), not one. 32 KB (`LayerStore`'s existing constant) holds ~30 contacts with ML-KEM material;
   both vault entries and a BEK record are far smaller, so 32 KB is still a generous starting point —
   but it must be picked against §10.5's tripwire (`VaultEntryType.document`/`.photo` stay commented
   out, or this design breaks), and only after §6's S5-then-S8 build order actually reaches S8.

3. **A trustee-count cap for `shardMetadata` — found 2026-09-02, not previously named.**
   `ShardDistributionMetadata.shards: [ShardRecord]` is variable-length, one record per trustee.
   Different depths will legitimately have different trustee counts — a duress layer the user never
   bothered setting up a decoy backup for has zero. Unpadded, that's a length leak of the same shape
   §5.4 already closes for the shard buffer: a near-empty `shardMetadata` compresses to a shorter
   plaintext than a fully-populated one, before the container's outer padding ever gets a chance to
   hide it, unless `shardMetadata` itself is padded to a fixed maximum trustee count first. A separate
   cap from item 2 above — this one bounds a field *within* the BEK record, not the container as a
   whole.

4. **Convention or cryptography for the BEK field's slot separation** (§5.1, Bug 92) —
   **re-examined 2026-09-02, splits into two applications with different blockers and costs.** The
   original framing ("hard-blocked, no slow KDF exists") doesn't fit this codebase's own architecture
   and should be dropped:

   **Why not a slow KDF.** `PIN+Manager.swift`'s existing verifier derivation is
   `HKDF(seKey, info: label ∥ pin)` — deliberately fast. `plan.md` records that PBKDF2 was tried for
   this exact purpose and removed: *"on-device code execution defeats any KDF regardless of iteration
   count... the 6-digit PIN space is brute-forceable in minutes on GPU independent of iteration
   count,"* with *"SE key prevents all off-device attacks"* doing the actual work instead. A slow KDF
   defends against an attacker with only the ciphertext and unlimited offline compute; binding
   derivation to the SE key removes that attacker entirely, since no candidate key is computable
   without the Enclave present. The same shipped pattern — HKDF over an SE key, PIN folded into the
   `info` parameter — is the fit here too, not a new primitive.

   **The live per-depth slot — looks buildable now.** Binding each slot's key to that depth's own PIN,
   the same way verifiers already are, closes the vault-key-extraction risk in §4: a session at depth 2
   only ever holds depth 2's PIN, so it cannot derive depth 0's slot key even with the vault key in
   hand — and neither can the app's own code, since PINs are checked against stored verifiers, never
   held in memory for a depth the session isn't at. This touches only local storage. It does **not**
   touch Shamir reconstruction (which splits raw `bekBytes`, independent of how any device seals them
   locally) or restore UX on a fresh device (which derives its own slot key under its own new PIN) — so
   neither cost below applies to this half.

   **The exported `.occbak` file (Bug 92's original proposal) — same mechanism, real recovery-contract
   cost, decide separately.** Folding the PIN into the *file's* wrapping key means a restorer needs
   both the Shamir-reconstructed `bekBytes` and the PIN active on the original device at export time —
   shards alone stop being sufficient, and rotating a PIN orphans every export made under the old one.
   Worth doing for the same reason as the live slot, but the cost is real and this half should not be
   adopted silently just because the live-slot half is now unblocked.

### Recovery-buffer-gated container (shard buffer + restore state)

5. **Slot size cap for the backup contents / pending-restore snapshot.** Fixed slots cap vault backup
   size. Pick the cap and enforce it at **export**, with a clear failure — not at restore, when the
   user has no vault left.

6. **Drop versus defer for non-shard payloads** behind the §5.3 gate. Shards retry (§5.3); messages do
   not. Deferring means storing the bundle, which is a cross-layer container again unless it too is
   slotted.

7. **Whether `CustodyShard` folds into this container.** Same key domain as the shard buffer, so
   likely the same file once decided — `LayerStore.md` already records its duress-mode accessibility
   as a deferred question, and §5.3's gate needs the same answer for it that it needs for BEK shards.

### Cross-cutting

8. **The `storePendingRestore` tombstone soft spot** — §11.3. A downgraded build can still *arm* a
   restore against a tombstoned row, because that one site uses `try?` where its siblings use `try`.
   Accept it, or add a guard distinguishing "no row" from "row present, undecryptable."

9. **Sequencing against Bug 105** — see §9. Live on shipped code now; closing it needs only stages 1–2
   of §7's BEK stages, independent of items 2–8 above and independent of §6's S5/S8 work.

---

## 9. Bug 105 — the sharpest evidence, and the one item with a clock on it

**Filed 2026-08-28, found while scoping this design — Open, High severity, reachable on shipped code
with no attacker-supplied file, no shard delivery, and no restore.**

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
  valid shares, but the device's record of who holds what is gone, `bekSetupState` reports his set,
  and shard health shows his phones.

This is the cleanest demonstration of §1's thesis, because every step is legitimate app behaviour. It
also answers open decision §8 item 1 empirically: a duress layer can distribute today, and it
distributes the real key.

**Its short-term remedy is genuinely unattractive**, which is an argument for this design rather than
against fixing it now: refusing distribution above depth 0 closes the harm but adds an observable
difference between layers — the trap two fixes already fell into the same week. Both options are
recorded rather than one being picked as the smaller diff.

**What actually closes it: only stages 1 and 2 of §7, not the full design.** Its own remedy is
specific — *"once each layer holds its own BEK, distributing at a duress depth distributes that
layer's key to that layer's contacts."* `prepareBEKShards` itself needs no change; it already calls
`fetchDecodedBEK` internally, so once that's depth-routed the fix is automatic. Not needed to close
this bug specifically: stages 3–6 (the restore side — Bug 99/93/95's territory), item 5's backup-
contents cap (different container), item 6 (Stage 3's problem), or item 4's convention-vs-cryptography
hardening (the baseline fix works fine with today's code-discipline separation). What Stage 1+2 does
need: §11.3's tombstone (can't leave the old device-wide row live) and §11.4's in-flight-restore
adoption (a restore can sit armed for days across the migration).

**Shard tracking comes along for free.** `ShardDistributionMetadata` (threshold + `[ShardRecord]`,
`Vault+Model.swift:80-100`) lives entirely inside `BackupEncryptionKey.Payload.shardMetadata` — not a
separate SwiftData table. `bekSetupState` and `bekShardMetadata()` are pure computed properties over
whatever `fetchDecodedBEK` returns, so once that's depth-routed both become depth-correct without
either function changing. (`PendingShardDistribute`/`queueDistribute` looked relevant but isn't — it's
a separate queue used only for per-entry vault PEK shares; BEK distribution builds and returns bundles
synchronously and never touches it.) Item 3's trustee-count padding is the one piece this doesn't give
for free — `shardMetadata`'s variable length still needs its own cap.

---

## 10. Bugs — past, expected, and traps to avoid

### 10.1 Bugs that led here

| Bug | What | Status |
|---|---|---|
| 88 | Backup ignored `visibleThroughDepth` in both directions | fixed — export and import are depth-scoped |
| 93 | Vault recovery was depth-blind in state, UI and trigger | fixed; its harm-4 follow-up is partly reverted by this design |
| 94 | Restore path trusted attacker-supplied material | all three remedies in — overwrite refusal, trustee attestation, confirmation |
| 94a | Remedy 2's attestation field unpadded — slot size named the trustee mid-recovery | fixed — every op ships an attestation, real or filler |
| 95 | One poisoned shard permanently blocks legitimate recovery | open — Bug 94 remedy 2 narrows the attacker population but doesn't close it; still no subset search, no discard-restore UI |
| 96 (item 1) | Two traps on decoded content | fixed |
| 96 (item 2) | Restore shard buffer unbounded | open — cap falls out of §5.4 |
| 96 (item 3) | Export plaintext left unzeroed | open |
| 99 | A coercer supplying his own trustees can test for duress | open — subsumed here except the pending-file tag |
| 100 r1 | Restore artifacts not excluded from device backups | fixed 2026-08-27 |
| 100 r2 | Shard file length was a keyless progress counter | fixed — rows; superseded by §5.1 slots |
| 100 r3 | `.occbak` length estimates vault size | open — moot once §5.2 slots the contents |
| 101 | `Documents/Inbox` copies retained and backed up | open — needs a device check |
| 92 | A backup file is readable from any layer (offline half) | open — complementary, see §4 and §8 item 4 |
| 102 | The BEK has no layer concept | **this document** |
| 105 | A duress layer can distribute shares of the real BEK | open — §9 |

**Adjacent, not this design's subject, but same root cause** — views and inbound paths that ignore
depth: Bug 103 (reader renders a hidden contact's name, phone, email) and Bug 104 (inbound identity
challenge renders a hidden contact's name). Both closed as duplicates of an accepted limitation, but
both are instances of "the depth dimension was not applied at the view layer," and §5.3's gate is the
server-side half of the same problem.

### 10.2 Anti-pairings

**Do not cap the restore shard buffer before the buffer is per-depth.** §5.4. This is the item most
likely to be picked up as obvious housekeeping by someone who hasn't read the reasoning, and it
introduces a cross-layer denial channel.

**Do not pad the `.occbak` (Bug 100 r3) before §5.2/§8 item 5 is decided.** If backup contents move
into slots, that file stops existing.

**Do not ship Bug 100 r1 alone.** It excludes the measurement while Bug 101 leaves the content unsealed
in `Documents/Inbox`. One device session verifies both.

### 10.3 Regressions this design must not introduce

- **Slot count must never vary**, in either container. N occupied slots readable as N layers, by count
  or by length, reintroduces the leak the padding exists to close.
- **Nothing may be created lazily.** §5.2. An artifact that appears when a feature is first used is a
  tell regardless of how well its contents are sealed.
- **Deferral must not be silently dropped.** Until Stage 5 lands, `attemptBEKRestore`'s depth guard is
  the only thing preventing a duress session from completing a depth-0-armed restore. The guard changes
  shape rather than disappearing.
- **No new depth-conditional UI.** Every prompt, banner and acknowledgment must read identically across
  layers unless the underlying state is genuinely per-layer. Two fixes in this area were themselves
  found to be new oracles — a confirmation shown only at depth 0, and a banner absent above it.

### 10.4 Known scope creep

The §5.3 gate applies to inbound processing generally, not to shards. Shards are the only payload with
a retry guarantee, so messages and prekeys need their own answer (§8 item 6). Expect Stage 3 to grow,
and do not let this get absorbed silently into it.

### 10.5 Tripwire

`VaultEntryType` has `document` and `photo` **commented out**. The whole fixed-slot design, in both
containers, rests on a vault backup being kilobytes. Enabling either makes the vault bulk data and
invalidates §5.1 entirely. That enum is the place to notice, so the constraint belongs as a comment
there too.

---

## 11. Migration and release scope

Settled 2026-08-28 for the BEK/recovery half. Records three decisions and the alternatives rejected to
reach them.

### 11.1 Release scope

Ships in **v1.10.3**, branch `v1.10.3/bek-layering-refactor` off `release/v1.10.3`. An earlier plan to
branch off `develop` was stale on its own terms: `develop` was 133 commits behind `release/v1.10.3` and
zero ahead at the time — branching there would have dropped every fix this design builds on, Bug 105's
filing included. (Both branches have since been merged; `develop` and `release/v1.10.3` no longer
diverge.)

The patch framing is a deliberate trade, not an oversight. Bug 105 is live, and its standalone remedy is
the unattractive one §9 describes. Shipping the full design instead of a patch that adds a tell is the
better of two imperfect options. What it costs: a patch version implies downgrade is safe, and after
this migration it is not — see §11.2.

### 11.2 Compatibility — what is achievable and what is not

Two directions, opposite answers. **New build reads old data — free, and required regardless.**
`BackupEncryptionKey.Payload` is `Codable`, sealed under the vault key; fields added as optional decode
against existing ciphertext untouched. **Old build reads what the new build wrote — impossible for
slot 0, by construction.** An old build keeps working only if the device-wide `BackupEncryptionKey` row
still holds the real key — but that row *is* Bug 105. Preserving it for downgrade preserves the exact
artifact this design exists to remove. No design resolves both directions at once.

The conflict is narrower than it first looks — only slot 0's BEK bytes:

| Piece | Old build's view | Verdict |
|---|---|---|
| Sibling slot files (depths ≥1, shard buffers, restore state, vault entries) | never heard of them, ignores them | duress-layer state *unavailable*, not lost; re-upgrading restores it |
| §5.3 visibility gate, §5.4 cap | behavioral, no persisted format | downgrade loses the gate, nothing else |
| Slot 0's BEK | the thing that must stop being device-wide | **breaks — see §11.3** |

**Add a `formatVersion` byte to each new file's sealed plaintext.** `ExportMetaSlotCodec` has none — a
gap worth not repeating. The project has no `VersionedSchema`/`SchemaMigrationPlan` at all, which also
argues for the file-based (not `@Model`-based) choice in §5.2 more strongly than §5.2 states on its
own: a file sidesteps the missing migration plan; a new `@Model` would sit on top of untested
lightweight migration and hope.

### 11.3 Tombstone the legacy row — do not delete it

When slot 0's BEK moves into the slot file, keep the `BackupEncryptionKey` row and overwrite
`encryptedPayload` with same-length filler. Deleting the row is itself a new tell — "this device once
had a BEK and no longer does." A filler-filled row is indistinguishable from a real one on cold disk,
satisfying §5.2's eager-creation rule instead of fighting it.

More importantly, a downgraded build then **fails closed at three of four sites**:

| Site | Behavior on a filler row | Why it matters |
|---|---|---|
| `setupBEK()` | guards on `existing.isEmpty` — row *presence*, not decryptability — so it no-ops | blocks the real harm: minting a fresh BEK with a new `distributionID`, silently invalidating the genuine trustee distribution |
| `currentBEK()` | throws | no export under a wrong key |
| `reconstructBEK` | uses `try`, not `try?` — decrypt failure propagates | reconstruction refuses |
| `storePendingRestore` | uses `try?`, so `alreadyHasBEK` reads false | **soft spot, §8 item 8** — a downgraded build still lets you *arm*. Recoverable, but handle it deliberately |

Net: downgrade degrades to *fails closed and says so*, not *works fine* or *silently destroys the
distribution*. That's the honest ceiling, and it's what §11.1's patch framing actually buys.

### 11.4 In-flight restores — adopt, do not dual-run

A restore can sit armed for days while trustees deliver shards in person. Losing that on update is a
real harm. **The destination is unambiguous** — a legacy in-flight restore is depth-0-destined by
construction, so it's adopted into slot 0 and finished by the new mechanism rather than kept alive on
the old path:

| Legacy state | Adopted as | Note |
|---|---|---|
| pending `.occbak` | slot 0's sealed backup contents | straight lift |
| `ReconstructShard` rows | slot 0's shard buffer | needs re-sealing — `deriveRecoveryBufferKey()` isn't depth-derived today while §5.1 requires depth in the HKDF info |
| completion at depth 0 | completion at slot 0 | same behavior, one path |

The re-seal needs the vault unlocked, so adoption runs at the **first depth-0 unlock after update**,
not at launch. Banked shards are adopted as-is, not re-validated against §5.3's gate — they predate the
gate but were already depth-0-destined and already passed Bug 94 remedy 2's attestation when banked;
re-validating risks dropping a shard from a trustee now hidden, delaying the exact restore this
protects. If adoption can't complete cleanly, refuse and ask the user to re-arm — a visible, identical-
at-every-depth cost, never a silent fallback to the old rules.

### 11.5 Rejected alternatives

**Dual-run** (legacy restores finish under legacy rules, new arms use the new mechanism) — rejected:
attacker-selectable and attacker-pinnable (arm before updating, keep every pre-design weakness on a
patched device); two completion paths that can disagree; and observable (different artifacts, different
timing, a proxy for device history).

**Complete-then-migrate** — strictly worse than dual-run. Migration gated on an event that may never
happen, and arming is something a coercer can do (Bug 99), so he can pin the device on the vulnerable
design indefinitely.

**Keep depth 0's BEK in the legacy row, slot only depths ≥1** — the one option with genuine downgrade
safety, still wrong: the row's presence then means "depth 0 has a BEK" while the file means "some other
depth does" — two artifacts of different shapes, §10.3's "slot count must never vary" leak wearing a
different hat.

### 11.6 Consequences for the stage plan

Stage 1 gains the tombstone (§11.3), the `formatVersion` byte (§11.2), and the adoption step (§11.4),
which runs at first depth-0 unlock with its own verify: a restore armed on the prior build, with shards
banked, completes after update without re-arming.

---

## 12. What this does not change

§10.5's tripwire becomes *more* load-bearing, not less, across this whole document. Today
`VaultEntryType`'s commented-out `document` and `photo` cases constrain a backup format that doesn't
exist yet. Under §6's candidate 3, they constrain the live vault-key-gated store too — an improvement:
one constraint, enforced where it breaks loudly, instead of an assumption two separate designs quietly
depended on.

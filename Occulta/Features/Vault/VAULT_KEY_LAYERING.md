# Vault-Key-Gated Storage — Vault Entries and the BEK Record

**Status:** BEK design complete; vault-entries (S8) key/array design resolved 2026-09-09 (item 11,
revised same day) — own array, own AAD, own codec, none of it extending or touching the BEK chain.
§8 now has twelve items — items 4 and 6 are superseded (by item 7 and item 11 respectively), preserved
for the record, not live decisions; §5's original one-array packaging is likewise superseded by item
11, preserved there too. Item 12 (2026-09-09) found contacts' Design B — which S8 is meant to reuse —
has no described mechanism for persisting a mid-session edit once its DB row is a dead shell; tracked
primarily in `plan.md`, cross-referenced here since S8 inherits it directly. Implementation started
2026-09-08 — Stage 1's core is built (see §7 table): the BEK array, its codec and AAD, and the wiring
into `fetchDecodedBEK`/`persistBEKPayload` with migration folded in. Stage 2's array-routing half is
now also built (item 10) — every listed function takes `currentDepth` except `updateBEKShardStatus`,
which deliberately takes none (searches all 32 slots instead, item 10). `reconstructBEK`/restore
completion remains blocked on `RECOVERY_BUFFER_LAYERING.md`'s Stage 4 (item 9). Item 7 settled
2026-09-07 (accept the cross-depth-reach risk; item 4's live-slot `slotKey` superseded, not built) —
item 11 (2026-09-09) found item 6's `entriesSlotKey` structurally incompatible with that same
full-array reseal, then, later the same day, found the one-array packaging itself wasn't the right
answer either. The duress-depth content-richness concern raised alongside item 7 is resolved —
accepted limitation, full reasoning in `Docs/Audit/OPEN_LIMITATIONS.md` §I. **Owner entries:**
`Docs/Features/Secure Mode/bugs.md` Bug 102 (BEK), Bug 105 (its sharpest evidence);
`forensic-trace-avoidance.md` S5 (contacts), S8 (vault entries). **Spec docs this changes:**
[`VAULT_BACKUP_GUIDE.md`](VAULT_BACKUP_GUIDE.md), [`VAULT_SSS_GUIDE.md`](VAULT_SSS_GUIDE.md) — both
describe the device-wide BEK/shard behavior this design replaces; see their own "Secure Mode" closing
sections, which point back here. **Compiled:** 2026-09-02, split out of `STORAGE_LAYERING.md` once
that doc's own container analysis showed this half and
[`RECOVERY_BUFFER_LAYERING.md`](RECOVERY_BUFFER_LAYERING.md) are independently buildable — see §7 for
exactly where they do and don't touch. Last decision recorded: 2026-09-09. **Release target
corrected 2026-09-07** — see §9: no longer `v1.10.3` (already shipped without this fix), now
`v1.11.0/vault-key-layering`.

**What this is.** Everything about the container sealed under the vault's biometric-gated key: sensitive
vault entries (if built) and the BEK record. Contacts (S5) aren't stored here — they use the existing,
separate Secure-Mode-keyed `LayerStore` — but their build is the recommended pilot for the lifecycle
this container's vault-entry half needs, so it's tracked here rather than a third document.

---

## 1. Why this is needed

**Recovery is device-wide, and so is most other sensitive storage, in an app that layers
*classification* almost everywhere else.**

Contacts, vault entries, group membership, PIN gates, and the layer arrays are all depth-partitioned
at the classification level — a `visibleThroughDepth` stamp gates what's shown. But the underlying
*storage* mostly isn't: one `BackupEncryptionKey` row, device-wide; live SQLite rows with plaintext row
counts and timestamps for both sensitive contacts (S5) and vault entries (S8). The classification layer
says what a session may see; underneath it the same bytes and row counts sit there for anyone who
reaches the raw storage.

**The evidence is the shape of every fix so far.** Across 2026-08-26/27 the restore flow alone was
patched five times — uniform confirmation prompt, uniform banner, deleted acknowledgment, filler
padding on shard ops, shards moved out of a length-leaking file. Every one of those flattens a
*symptom*. None removes it. Two were later found to have introduced a new tell while closing an old
one — the signature of patching a structural problem at the surface.

---

## 2. What is and is not layered today

| Thing | Scope | Consequence |
|---|---|---|
| Sensitive contacts (S5) | `visibleThroughDepth` + UI filter classify; rows stay live, readable under the canonical DB key | a raw SQLite read on an unlocked device sees every sensitive contact regardless of depth |
| Vault entries (S8) | `visibleThroughDepth` (exact-match) classifies, stamped at activation Step 8; `id`/`createdAt` are plaintext columns | row count and creation timestamps are identical at every depth — not depth-gated at all |
| Restored vault entries | **per depth** — `importBackup` stamps `visibleThroughDepth`, exact-match | contents are correctly contained (this part already works) |
| `BackupEncryptionKey` | one row, device-wide, no depth stamp | a restore completing in duress installs the device's real backup key |
| `shardMetadata` | inside the BEK payload, so device-wide | the trustee list is shared across layers |
| Shard *distribution* | no depth gate at all | **a duress layer can distribute shares of the real BEK — see §6** |

`shardMetadata` is distribution *bookkeeping* (who has a share, its status) — it does not hold shard
values. Restore-side shard collection is a different container; see `RECOVERY_BUFFER_LAYERING.md`.

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

That last point answers "we should not impose caps, we need graceful flexibility." A fixed envelope
isn't negotiable — it's what makes an occupied slot indistinguishable from an empty one. What *is*
negotiable is whether the user can see the budget as they spend it; this codebase already chose "yes"
for contacts.

**What `LayerStore` deliberately does not hold:** vault per-entry keys, prekeys, or `CustodyShard`
records — see §4 for why the first of those is load-bearing.

---

## 4. The protection domains

`LayerStore.md` excludes vault per-entry keys deliberately: *"Storing them would widen the attack
surface since a store compromise requires only the SE Secure Mode key, bypassing the biometric gate
that otherwise protects vault content (Bug 8)."* Verified in `Key+Manager.swift` rather than taken from
prose — three domains, not two, and this is why this container exists separately from both
`LayerStore` and `RECOVERY_BUFFER_LAYERING.md`'s container:

| Key | Derived by | Biometric gate | Seals today |
|---|---|---|---|
| Secure-Mode key | (existing) | No | Contact `LayerStore`, local DB key |
| **Vault key** | `deriveVaultKey(context: LAContext)` | **Yes** | Vault entry content (`VaultManager.currentKey()`) — **and the BEK record itself, per §5's table** |
| Recovery buffer / shard custody key | `deriveRecoveryBufferKey()` — no `LAContext` | No | `CustodyShard`, shard buffer, restore/arming state — see the other doc |

**Putting vault entries into the existing Secure-Mode-keyed store would collapse the first two domains
and strictly downgrade vault protection.** It's also why S8 is rated below S5: a duress-PIN-only coercer
cannot open the vault at all, so the row-count tell needs duress PIN *and* forced biometrics to be
reachable — see §4a for why that bar may be lower than it looks for this app's actual threat model.

**Not only a cold-disk risk.** A coercer who compels biometric auth causes `deriveVaultKey` to hand the
derived `SymmetricKey` to the app process, in ordinary memory, for the duration it's used. Extracting
it needs forensic tooling — jailbreak plus debugger, or GrayKey/Cellebrite-class extraction — not a
break of the Enclave; the private key never leaves it. But this project's own threat model already
assumes exactly that capability for the local DB key (`forensic-trace-avoidance.md` S1). With the vault
key alone, a coercer at depth 2 could in principle decrypt every other slot in *this* container,
including `shardMetadata` — trustee counts and identities — at depths they were never meant to see.

### 4a. Is "duress PIN + forced biometrics" actually the high bar S8 assumes? — unverified claim, not a finding

Raised as a question, not settled here. S8's downgrade rests on that compound attack being harder than
PIN coercion alone. The counter-argument — that biometric unlock is compellable under a lower legal bar
than a memorized PIN in some jurisdictions, so the compound attack may be closer to the default
coercion pattern than a stacked edge case for this app's stated threat model — is a **legal claim**,
not a technical one, and has not been checked against actual counsel or jurisdiction-specific sourcing.
Route it through the same counsel pass `Docs/Audit/OPEN_LIMITATIONS.md` Section E already queues for
duress/coercer language; don't treat it as established reasoning on the strength of sounding plausible.
What *is* verified, independent of this claim: the failure mode itself — the UI showing "No entries
yet" while the raw DB holds N rows — is real regardless of how the legal question resolves.

---

## 5. Target design

**BEK: one fixed-width array of fixed-count slots, one slot per depth**, sealed under the vault key.

**Vault entries, if built, get their own equivalent array, not a shared slot in this one — reopened by
item 11, 2026-09-09.** The table below described one array with two separately-sealed fields per slot;
that's superseded. Preserved for the record, not the current design:

| Field | Notes |
|---|---|
| BEK record | `bekBytes`, `distributionID`, `shardMetadata` — capped and padded, see §8 |
| ~~Sensitive vault entries (if built)~~ | ~~canonical copy; DB rows become unreadable shells~~ — see item 11 |

DB rows becoming unreadable shells and the canonical copy living off-DB both still hold — only the
"one array, two fields" packaging is what item 11 reopened.

**Two record types don't force two containers — nor do they require one, once item 11 weighed the
actual costs on each side.** The rest of this paragraph is the original, one-container reasoning,
preserved for the record: preserving a sealed field never requires its own key — one array is fewer
artifacts to pad, clean up, and explain than one per feature.

**Every sealed field's AAD must bind its slot index.** Without it, lifting slot 2's ciphertext into
slot 0 moves a duress layer's BEK — or vault entries — into the real one. **With BEK and vault entries
in separate arrays (item 11), slot-index binding alone is sufficient within each array — but the two
arrays' AAD domain strings must differ from each other too, or a slot-N ciphertext from one array
would authenticate if pasted into the other array's slot N under the same `vaultKey`. See item 11.**

**Concrete design, built 2026-09-07: `BEKSlotAAD`, in `Vault+Manager+Backup.swift`.** 20-byte domain
separator (`"occulta-bek-slot-v1"`) plus a 1-byte slot index — checked against this codebase's other
depth/slot mechanisms first, not assumed: neither `Manager.LayerStore.pop()` nor `AppLayerConfig`'s
verifiers seal with any AAD at all, so this is a genuinely new pattern here, not a reuse of an existing
one. Deliberately excludes `formatVersion` — that already lives inside the sealed plaintext (item 3's
byte 0–1) and is checked there post-decryption; a slot-swap attack moves ciphertext between two slots
written at the same format version, so slot-index binding alone is what stops it. Its 32-slot range is
its own constant, not `AppLayerConfig.maxVerifierCount` — the two coincide today (one BEK slot per
depth, one verifier per depth) but reusing that constant would make BEK key material depend invisibly
on a verifier-array-sizing decision made for unrelated reasons elsewhere. Tested directly:
`AES.GCM.seal` under slot 2's AAD, then `.open` under slot 0's, throws — the actual property this
exists for, not just that the two byte strings differ.

**This container cannot get cryptographic per-depth separation for free.** The vault key is not
depth-derived, and making it so touches every vault entry. §8 item 4 has the remedy and its two
applications.

**Where it lives:** a `LayerStore`-shaped sibling file, not `AppLayerConfig` — that row is read on
essentially every security check and SwiftData loads the whole row, so bulk payloads would ride along
with every `requireConfig()`. Eagerly created from first launch, same reasoning as §3.

**Found 2026-09-05: no dedicated directory, no magic byte — disambiguate by which key opens it.**
The trace below is what led to §8 item 5's decision; see that item for the settled outcome. Checked
the existing precedent directly
(`AppGroupLayerStoreBackend.swift:26-53`) rather than assume: the current contact blob already lives in
its own dedicated directory (`"blobs"`), holds nothing else, and `findFile(in:)` just reads whatever
single file is there — filename is a fresh UUID on *every* write, old file deleted only after the new
one lands, no magic byte, no stored path. That's most of the way there, but the dedicated directory
itself is a residual signal: an examiner who has read this app's source sees a purpose-named folder and
learns "a concealment subsystem lives here" from structure alone, before touching a single byte. Once
this container and `RECOVERY_BUFFER_LAYERING.md`'s exist alongside it, that becomes two or three
purpose-named folders — architecture leaking through directory layout, not content.

**The stronger version:** one shared, undifferentiated pool for all of them — same directory, same
random-renamed-on-every-write naming, same fixed size (§8 item 3's cross-container sizing note) —
disambiguated purely by
which of the app's own keys successfully opens a given file via `AES.GCM.open`. No magic byte required;
GCM's own authentication tag already distinguishes "wrong key" from "right key" for free, which is a
cleaner signal than a magic byte would be anyway, since a magic byte is plaintext-visible before any
key is involved at all. Cost is a handful of trial decryptions per lookup — computationally trivial for
a fixed, small key set (vault key, recovery-buffer key, Secure-Mode key). Pool file *count* must stay
fixed regardless of configuration, matching the eager-creation principle already used everywhere in
this design, so count doesn't become a new signal in place of the directory-name one it replaces.

**Settled 2026-09-06 (§8 item 5): take it all the way — one shared pool**, not the intermediate
same-directory-different-name option. Folding the recovery-buffer container and the existing contact
blob in requires `RECOVERY_BUFFER_LAYERING.md`'s own "where it lives" section to adopt the same
approach, which it doesn't yet — tracked there as a dependency, not a new open question here.

### 5.3 What happens to the container across exports at multiple depths — confirmed 2026-09-06

Nothing shared, nothing observable. Two exports at two different depths are fully independent
operations, and neither writes to this container at all:

- **Vault entries** are read from memory, not from a fresh container read. Per §8 item 6, a depth's
  `entriesSlotKey` is derived once at the moment that depth's PIN is verified, and — mirroring
  contacts' Design B exactly, "loaded into memory on normal unlock" from the blob — that depth's
  entries get decrypted from its own slot into memory at that point, not re-read from the file on
  every subsequent access. By the time an export runs, the current depth's entries are already sitting
  in memory; export reads that in-memory copy, the same data the Vault tab is already displaying.
- **The BEK** *is* read from the container at export time — `currentBEK()`/`fetchDecodedBEK`, routed
  per-depth by Stage 2 — but that's a read, identical in shape to what `exportBackup` already performs
  today against the device-wide row. Nothing about export writes to the container.
- **What does get written on every export** is the separate, pre-existing `backup-export-meta.dat`
  staleness tracker — its own 32-slot fixed file, one slot per depth, predating this whole design.
  Exporting at depth 2 writes slot 2 there; exporting at depth 0 writes slot 0. Full regeneration on
  every write means that file's mtime moves regardless of which depth exported — expected, and already
  covered by the same reasoning applied elsewhere in this design (`B2`'s timestamp normalization), not
  a new consideration this raises.

So: exporting at multiple depths, in any order, any number of times, leaves this container completely
unchanged in shape and content — regardless of what its final total size (§8 item 2) turns out to be.

---

## 6. Bug 105 — the sharpest evidence, and the one item with a clock on it

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
  backup, iCloud, or Bug 101's `Documents/Inbox` copy (see the other doc).
- Immediate: `prepareBEKShards` reuses the existing `distributionID` and **overwrites**
  `shardMetadata`, so the owner's real trustee list is replaced by his. Genuine trustees still hold
  valid shares, but the device's record of who holds what is gone.

This is the cleanest demonstration of §1's thesis, because every step is legitimate app behaviour. It
also answers open decision §8 item 1 empirically: a duress layer can distribute today, and it
distributes the real key.

**Its short-term remedy is genuinely unattractive**, which argues for this design rather than against
fixing it now: refusing distribution above depth 0 closes the harm but adds an observable difference
between layers — the trap two fixes already fell into the same week.

**What actually closes it: only stages 1 and 2 of §7 — entirely within this container.** Its own
remedy is specific — *"once each layer holds its own BEK, distributing at a duress depth distributes
that layer's key to that layer's contacts."* `prepareBEKShards` needs no change; it already calls
`fetchDecodedBEK` internally, so once that's depth-routed the fix is automatic. Not needed to close
this bug: anything in `RECOVERY_BUFFER_LAYERING.md` (the restore side — Bugs 99/93/95's territory), or
item 4's convention-vs-cryptography hardening (the baseline fix works fine with today's code-discipline
separation).

**Shard tracking comes along for free.** `ShardDistributionMetadata` (threshold + `[ShardRecord]`,
`Vault+Model.swift:80-100`) lives entirely inside `BackupEncryptionKey.Payload.shardMetadata` — not a
separate SwiftData table. `bekSetupState` and `bekShardMetadata()` are pure computed properties over
whatever `fetchDecodedBEK` returns, so once that's depth-routed both become depth-correct without
either function changing. (`PendingShardDistribute`/`queueDistribute` looked relevant but isn't — a
separate queue used only for per-entry vault PEK shares; BEK distribution builds and returns bundles
synchronously and never touches it.) Item 3's trustee-count padding is the one piece this doesn't give
for free — `shardMetadata`'s variable length needed its own cap, settled there (10 write / 255
storage, 42-byte fixed record).

---

## 7. Build stages, and where they touch the other container

| # | Stage | Verify | Touches `RECOVERY_BUFFER_LAYERING.md`? | Status |
|---|---|---|---|---|
| 1 | Slotted BEK array here, seeded with filler at first launch. Migrate the single `BackupEncryptionKey` row into slot 0 | array length identical whether 0 or 32 depths hold a BEK; existing export/import tests pass against slot 0 | No | **Built, 2026-09-08.** `BEKPayloadCodec` → `BEKSlotAAD` → `AppGroupBEKArrayBackend` (own directory, item 8) → `BEKArray` (item 7's full-array reseal, item 8's throw-on-corruption fix) → wired into `fetchDecodedBEK`/`persistBEKPayload`, migration folded in. `RotationRegistry` checked, not just assumed — `BackupEncryptionKey` stays correctly in `notRotated` since the row and the new array file are both still sealed under the vault key, unchanged; `RotationRegistryTests` passes as-is. |
| 2 | Route BEK access by depth — `fetchDecodedBEK`, `setupBEK`, `currentBEK`, `bekSetupState`, `bekShardMetadata`, `exportBackup`, `reconstructBEK` | a BEK created at depth 2 is invisible at depth 0 and vice versa | No | **Split, found 2026-09-08 (item 9). Array-routing half built 2026-09-08 (item 10).** `fetchDecodedBEK`, `persistBEKPayload`, `setupBEK`, `currentBEK`, `bekSetupState`, `bekShardMetadata`, `prepareBEKShards`, `distributeBEKShards`, `rotateBEK`, `exportBackup`, `refreshBackupStaleness` all take `currentDepth: Int` with no default. `updateBEKShardStatus` deliberately does **not** — found mid-build that "whatever depth is current" cannot locate a trustee's confirmation reliably even in the ordinary case (a confirmation for depth 0's distribution can arrive while any other depth is active); it now searches all 32 slots for the attributeID instead (item 10). All UI call sites (`Vault+Tab.swift`, `Vault+ShardSetup.swift`, `VaultRecoverySettings.swift`) updated; `recomputeRecoveryHealth`'s auto-save-triggered path split so `bekErosion` — now depth-scoped — isn't computed from a depth-blind trigger (item 10). `reconstructBEK` specifically is still blocked on `RECOVERY_BUFFER_LAYERING.md`'s own per-depth restore state (its Stage 4) — cannot be finished correctly in isolation here. |
| — | Vault entries: contacts' Design B first (§8 candidates), then this container's own equivalent array | see §8 | No | Not started. Key/array design resolved 2026-09-09 (item 11, revised same day) — own array (`VaultEntriesArray`, provisional), own AAD (`VaultEntriesSlotAAD`, provisional), own codec (`VaultEntriesPayloadCodec`, provisional), sealed under plain `vaultKey` — `BEKArray`/`BEKPayloadCodec`/`BEKSlotAAD`/`AppGroupBEKArrayBackend` are all reused as reference shape, not extended or touched. Slot format, growth mechanism, and migration sizing settled in item 2. Still needs: S5 (contacts' Design B) built first per the candidates decision below, including item 12's found gap (no mechanism to persist a mid-session edit — plan.md item 4); `entriesSlotKey`'s in-memory-cache mechanism is moot (item 11) so no per-depth key cache to build; the backend's hardcoded directory constant made configurable for a second file; UI-level count/size enforcement (item 2). |
| 5 | Completion per layer | a restore armed at depth N completes at N and nowhere else | **Yes — the only join point.** Reads collected shares from the other container, writes the reconstructed BEK into this one's slot | Not started. |

**Acceptance criterion for the whole design (both containers):** a coercer can arm, set up his own
trustees, collect and complete a restore in his layer, and see exactly what a working app does —
because it *is* a working app in that layer, not a simulation of one.

**Testing and migration requirement, every stage — settled 2026-09-07.** A stage isn't done once it
builds. It's done once (a) tests cover the behavior in its `Verify` column, and (b) if the stage
touches existing on-device data (Stage 1's legacy-row migration, any future entry-count expansion from
item 2), there's an explicit migration plan checked for data loss, not just assumed safe by the design
reasoning above. This data has no other copy if a migration goes wrong.

**Release target — corrected 2026-09-07: `v1.10.3` already shipped without this fix.** §9 originally
scoped this as a `v1.10.3` patch, on `v1.10.3/bek-layering-refactor` off `release/v1.10.3`. That branch
merged — design consolidation and bug filing only, not Stages 1-2's actual implementation — and
`release/v1.10.3` has since shipped with Bug 105 still open. The fix now belongs on the current branch,
`v1.11.0/vault-key-layering` off `release/v1.11.0`. Full migration/release-scope reasoning, including
the legacy-row tombstone this container's Stage 1 needs, is in §9.

---

## 8. Open decisions

1. **Per-depth shard distribution — settled 2026-09-02.** Does each layer carry its own trustee set?
   May a duress layer distribute at all? What does a trustee see when holding shards for two of the
   owner's layers? Resolved without new design:
   - **Own trustee set per layer: yes, for free.** `shardMetadata` becomes per-depth automatically once
     the BEK is slotted. The contact picker feeding `prepareBEKShards(threshold:recipients:)`
     (`Vault+Manager+Backup.swift:368`) already filters by `isVisible(atDepth:)`. The key itself was the
     only device-wide thing — Bug 105's exact finding.
   - **Duress-layer distribution: allowed uniformly at every depth.** Refusing it above depth 0 is a
     depth-conditional behavior — the same trap two other fixes fell into the same week. Once the BEK
     is depth-scoped, distributing at depth N distributes depth N's own decoy key — nothing left to
     leak.
   - **Same trustee holding shards for two layers: already handled, nothing depth-aware needed on the
     trustee side.** `visibleThroughDepth` is a ceiling (`value >= depth`), so a contact visible at both
     depth 0 and depth 2 is the normal case. `CustodyShard` stores shards keyed by an opaque row id with
     no contact linkage in plaintext, and already tolerates multiple live shards from one owner.
   Net: nothing new to build for this decision — a consequence of the design above plus the existing
   trustee model.

2. **The container's overall slot budget — settled 2026-09-07: dynamic (option B), per-entry size
   1,051 bytes.**

   **Per-entry content: 1024 bytes, fixed, not expandable.** Unlike entry count, size is bounded by
   content type (seed phrases, key tokens, short notes), and `§11`'s tripwire already draws the line
   at "kilobytes, text-only." A single generous fixed number covers the realistic range without the
   added complexity of a second growable dimension. Encoded as a `UInt16` length prefix (not `UInt8` —
   256 doesn't fit in a byte, and a growable *count* alongside a fixed *size* only works cleanly if the
   size field itself has headroom to spare, which `UInt16`'s 65,535-byte ceiling provides by a wide
   margin). **Per-entry record: 1,051 bytes** (16 `id` + 8 `createdAt` + 1 type tag + 2 length prefix +
   1024 content).

   **Entry count: dynamic, expandable in increments of 32 — chosen over a hard ceiling (option A)
   after checking real shipped-code state, not picked arbitrarily.** A hard ceiling was considered
   first (128 discussed, matching the BEK capacity/policy split's shape), but unlike the BEK's 255 —
   the actual Shamir mathematical ceiling — no equivalent provable ceiling exists for vault entries.
   Checked against the current codebase rather than assumed: `VaultManager.addEntry`
   (`Vault+Manager.swift:217-265`) enforces no count limit today, and entry creation has none of the
   friction (no key ceremony, no UWB exchange) that naturally bounded real-world BEK trustee counts —
   a real install could plausibly already hold well over 128 entries at one depth. A hard ceiling risks
   the one outcome this design treats as unacceptable everywhere else: guessing a fixed number that
   turns out too small and truncates real user data on migration, with no telemetry available to
   verify the guess in advance. Dynamic sizing avoids the guess entirely — each install grows to
   wherever its real data already sits, by construction, rather than needing the number to be right on
   the first try.

   **Migration must account for legacy counts already above 32, not just future growth.** Stage 1's
   one-time conversion from today's uncapped storage into the new fixed-slot format must size each
   depth's *initial* slot to `max(32, ceil(existingCount / 32) × 32)`, not assume every install starts
   at exactly 32 — otherwise the same truncation risk a hard ceiling would have created reappears at
   the very first migration instead of at some future growth point.

   **Growth mechanism: expand by 32, rewriting all 32 depth slots of *this* container at once** —
   required by §11's "slot count must never vary," not an added precaution — using the same
   `formatVersion`-driven migration this design already relies on elsewhere (bump the version, read
   the old fixed shape, re-seal into the new one, adopt at the next safe unlock). Per item 5's
   shared-pool requirement, a growth event here cascades into resizing the recovery-buffer container
   and the migrated contact blob too, since all three pool files must stay the same size — a real,
   recurring cost each time ordinary usage crosses a threshold, accepted as the tradeoff for never
   needing to guess a ceiling.

   **Container total, at the 32-entry starting point: `33,632` (vault entries) + `10,761` (BEK record,
   item 3) = 44,393 bytes/depth** — already exceeds both candidates item 3 was weighing before vault
   entries had a real shape (10,789 efficient, 32,768 matching), so this container's slot size is no
   longer "32 KB, matching `LayerStore`." One expansion (32 → 64) pushes this to 78,025 bytes/depth.
   `RECOVERY_BUFFER_LAYERING.md`'s own container (56,065 bytes/depth at the same starting point, item 7
   there) is larger by a constant 11,672 bytes at every entry count, since both containers scale by the
   same per-entry term — so the shared-pool floor is always `RECOVERY_BUFFER_LAYERING.md`'s number, and
   this container (plus the migrated contact blob) pads up to match it, not the other way round.

   **UI enforcement required, not yet built.** Same two-layer pattern as the trustee cap (§6 of the
   sibling doc, and the reverted `9493c85`): a storage-level guard throwing before any write, plus
   UI-level enforcement — a live count indicator, input capped or disabled at the per-entry length
   limit — so neither the per-entry size nor the count-driven resize is ever discovered as a runtime
   error instead of a visible budget.

   **Not yet implemented.** Decided, not built — same status as items 3-6 above.

3. **A trustee-count cap for `shardMetadata` — found 2026-09-02, settled 2026-09-05: cap 10 (write
   policy) against a 255-share storage ceiling, fixed-byte wire format below.**

   `ShardDistributionMetadata.shards: [ShardRecord]` is variable-length, one record per trustee, and
   `prepareBEKShards`/`distributeBEKShards` bound `recipients.count` nowhere today. Different depths
   legitimately have different trustee counts — a duress layer never set up for backup has zero — so
   unpadded, a near-empty `shardMetadata` compresses shorter than a full one, before the container's
   outer padding gets a chance to hide it.

   **Cap = 10.** Comfortably above any realistic Shamir trustee count (consumer social-recovery schemes
   typically run 3–9 guardians) while keeping padding cost negligible in this container. The
   cryptographic ceiling — confirmed in `ShamirSecretSharing.swift`, `UInt8` x-coordinates — is 255
   shares and was never the number this was sized against.

   **Wire format — fixed-byte binary, not JSON/`Codable` as `Payload` is today.** A first pass at this
   used `Payload`'s existing `Codable` shape plus a computed pad-to-target step, which turned out to be
   the wrong instinct: `ShardStatus`'s `String` rawValues alone run 4–13 characters
   (`"lost"` vs. `"revokePending"`), a 9-byte-per-record spread that a JSON-encode-then-pad approach
   would have to bound correctly by hand and re-verify every time a case is added or renamed — exactly
   the kind of thing that quietly breaks later. Fixed byte offsets close this structurally instead of
   by computation. Per-trustee `ShardRecord`:

   | Field | Bytes | Encoding |
   |---|---|---|
   | `contactIdentifier` | 16 | raw UUID bytes, not the 36-char string |
   | `attributeID` | 16 | raw UUID bytes |
   | `status` | 1 | `UInt8` tag, not the enum's string rawValue |
   | `distributedAt` | 9 | 1 presence byte + 8-byte `UInt64` epoch seconds, always both, zero-filled when absent — **never 8 bytes when absent and 9 when present; that byte-count difference is itself the leak** |
   | **Total** | **42** | — |

   **Storage capacity and write policy are two different numbers — settled 2026-09-05.** The array's
   *storage* capacity is **255**, the Shamir ceiling itself (`UInt8` x-coordinates,
   `ShamirSecretSharing.swift`) — not an arbitrary "generous" guess, the literal hardware/math limit of
   what could ever exist, since the library itself refuses to produce more. `prepareBEKShards`'s
   *write-time guard* still enforces **10** for anything new or redistributed. These don't need to
   match, and forcing them to would recreate the exact problem below.

   `Payload` overall, at capacity: `formatVersion` (`UInt16`, 2) + `bekBytes` (32) + `distributionID`
   (16) + `threshold` (1, `UInt8` comfortably covers 2–255) + shards array (`42 × 255 = 10,710`) =
   **10,761 bytes plaintext, always** — every slot, every device, whether it holds 0 real records or
   255, regardless of write-time policy. This changes `Payload`'s encoding project-wide, not just
   `shardMetadata` — worth noting against §5's table, which doesn't currently specify one.

   **Why 255 and not 10: the over-cap question this resolves.** A legacy distribution created before
   any cap existed could hold any count up to Shamir's own limit. Sizing storage to the *write* policy
   (10) would mean Stage 1's migration literally cannot represent a legacy distribution larger than
   that — no fixed-width encoding is at fault here, there'd just be nowhere to put the 11th record.
   Sizing to 255 makes that scenario impossible by construction rather than needing a remedy: a legacy
   distribution of any size Shamir could ever have produced fits, unconditionally, forever. Nothing is
   truncated, nothing is silently reduced, no trustee is ever dropped without the owner choosing it —
   reading and reconstructing an over-cap legacy distribution is permanently unaffected. The only
   consequence: redistributing or updating one is still capped at 10 by the write guard, same as any
   fresh distribution — reduce first if there's ever a reason to change it. This was framed as two
   options (A/B) before working through the actual numbers; it isn't a tradeoff once the true ceiling
   (255) turns out to cost only ~10.5 KB either way.

   **Measured, not estimated — real `JSONEncoder()` output for today's `Codable` scheme, same encoder
   the codebase actually uses (`Vault+Manager+Backup.swift:1016`), against the fixed design above:**

   | Trustees | Current (JSON) — best case¹ | Current (JSON) — worst case² | New design, fixed-width³ |
   |---|---|---|---|
   | 0 | 159 → ciphertext 187 | 159 → ciphertext 187 | 10,761 → ciphertext **10,789** |
   | 5 | 808 → ciphertext 836 | 1,018 → ciphertext 1,046 | 10,761 → ciphertext **10,789** |
   | 10 | 1,459 → ciphertext 1,487 | 1,877 → ciphertext 1,905 | 10,761 → ciphertext **10,789** |
   | 255 | 33,310 → ciphertext 33,338 | 43,988 → ciphertext 44,016 | 10,761 → ciphertext **10,789** |

   ¹ Every `distributedAt` nil — Swift's synthesized `Codable` uses `encodeIfPresent`, so a nil optional
   omits the key entirely rather than writing `null` — and every `status` the shortest rawValue
   (`"lost"`, 4 chars). ² Every `distributedAt` set (adds the key plus a `Double` timestamp) and every
   `status` the longest rawValue (`"revokePending"`, 13 chars). ³ Genuinely constant at every count
   0–255 and every status/timestamp combination — that's the entire point being measured.

   **Cross-container forensic concern, found 2026-09-05: don't let this container's *own* efficient
   size become a fingerprint.** 10,789 bytes is cheap relative to the contact `LayerStore`'s existing
   32 KB per slot, but if this container settles on its own tighter number, an examiner who knows both
   values can identify "this file is the BEK+entries container" purely from its distinct size, same
   problem as trustee count leaking via length, one level up. Reusing `LayerStore`'s existing 32 KB
   constant here instead — rather than the cheaper 10,789 — costs roughly 22 KB × 32 slots ≈ 700 KB of
   otherwise-unneeded padding, trivial on-device, in exchange for making this container and the contact
   blob byte-identical in size. Not yet decided whether to take the cheap number or the matching one;
   leaning matching, given the cost is negligible and the alternative reopens the fingerprinting
   question item 5 below also raises for directory structure.

   **Superseded 2026-09-06 — the "10,789 vs. 32 KB" framing no longer applies**, and **resolved
   2026-09-07** now that item 2 has settled. Item 2's vault-entry sizing (1024 bytes/entry, dynamic,
   starting at 32) put the real per-depth floor at **44,393 bytes at the starting point** — both this
   item's efficient (10,789) and matching (32,768) candidates were already too small. Both container
   sizes are now known: this container starts at 44,393 bytes/depth, `RECOVERY_BUFFER_LAYERING.md`'s
   starts at 56,065 (its item 7) and is larger by a constant 11,672 bytes at every future entry count.
   Per item 5 (file-identity), this container and the migrated contact blob pad up to match the
   recovery-buffer container's size at every growth step — see item 2 for the full numbers.

   **`formatVersion` — folds the padding rule into the byte a decoder already needs to trust**, rather
   than inventing a separate cap-version concept. `formatVersion = 1` means "capacity is sized to the
   255 ceiling, write policy is 10"; a future change to either bumps it. Absence of the field entirely
   (not `0` — genuinely absent) marks the legacy, pre-slotting device-wide row, which predates the whole
   concept and is distinguishable from it on that basis alone.

   **Not yet implemented.** A first pass shipped `prepareBEKShards`'s guard and matching UI enforcement
   without this wire-format work or the storage-capacity question behind it — reverted (`2b49457`) once
   the gap surfaced. Nothing about the numbers or wire format above is code yet.

4. **Convention or cryptography for the BEK field's slot separation** (Bug 92) — splits into two
   applications with different blockers and costs. **Live-slot half superseded 2026-09-07 by item 7 —
   not built, accepted as code-discipline separation instead. Exported-file half still decided
   2026-09-06 (ship opt-in, 6-word passphrase), unaffected, not implemented yet.**

   **Why not a slow KDF** (still applies to the exported-file half). `PIN+Manager.swift`'s existing
   verifier derivation is `HKDF(seKey, info: label ∥ pin)` — deliberately fast. `plan.md` records
   PBKDF2 being tried for this exact purpose and removed: *"on-device code execution defeats any KDF
   regardless of iteration count... SE key prevents all off-device attacks"* doing the actual work
   instead. Binding derivation to the SE key removes the offline-brute-force attacker entirely; the
   same shipped pattern fits here too, not a new primitive.

   **The live slot — originally decided 2026-09-05, superseded 2026-09-07 by item 7. Preserved below
   for the record, not built.** Same fold-PIN-into-`info` convention the verifier already uses, applied
   to the slot key instead of a verifier: `slotKey(depth) = HKDF(inputKeyMaterial: vaultKey, info:
   "bek-slot" ∥ depth ∥ pin(depth))`. A session at depth 2 holds the vault key (from biometric auth,
   not depth-specific) and depth 2's own PIN — it never holds depth 0's PIN, so it cannot compute
   depth 0's `slotKey` even though it holds the same vault key depth 0 would use. This would have
   closed §4's vault-key-extraction risk cryptographically rather than by code discipline alone — but
   item 7 found that exact isolation makes it impossible to hide *which slot is actively written*
   across snapshots, since hiding that needs every slot re-sealable with fresh nonces regardless of
   which depth's session is writing. The two properties can't both hold; item 7 settled 2026-09-07 on
   keeping the write-pattern protection and accepting code-discipline-only separation instead, matching
   `Manager.LayerStore`'s existing posture for contacts (Bug 106). See item 7 for the full reasoning.

   **Not yet implemented — and now won't be, as designed above.** The exported-file half remains
   decided and pending implementation; the live-slot half above is superseded, kept only as a record of
   what was considered and why it was set aside.

   **The exported `.occbak` file (Bug 92's original proposal) — decided 2026-09-06: ship as an
   opt-in, 6-word passphrase, not a PIN.** Revises the original `slowKDF(PIN, ...)` proposal on two
   points worked through in design:

   **Passphrase, not PIN — and reuses existing infrastructure.** `Manager.PassphraseGenerator`
   (`Passphrase+Manager.swift`) already exists, already shipped for the UWB pairing ceremony's Diceware
   confirmation — EFF large wordlist (7776 words), `SecRandomCopyBytes`-backed generation, no new
   dependency. At 6 words (log2(7776) × 6 ≈ 77.5 bits, vs. a 6-digit PIN's ≈ 19.9), this is comfortably
   past feasible even for dedicated state-actor-scale offline brute force — rough estimate, generous
   assumptions, ~60 years at 10¹³–10¹⁴ guesses/second, versus low single-digit days for 5 words. 6
   chosen deliberately over the function's own 5-word default for that margin. **A fresh passphrase
   generated per export, not the app's own unlock PIN** — shown once at export time, the user saves it
   themselves. This also removes the original proposal's "PIN rotation orphans old exports" cost
   entirely: it's independent of the app PIN, so rotating that PIN never touches a past export.
   Sufficient entropy also removes the slow-KDF question from before — plain `HKDF`, the same pattern
   used everywhere else in this design, is enough once the input itself carries 77.5 bits.

   **What this actually protects, stated precisely rather than implied more broadly — the scope
   decision that makes shipping it defensible.** Entropy defends against an adversary who obtains the
   exported file *without* the owner's cooperation — found in `Documents/Inbox` (Bug 101), intercepted
   from a device backup, or a subset of trustees compromised independently. It defends nothing against
   a coercer who has the owner detained: a human-memorizable secret can be compelled from the one
   person allowed to know it, same reason duress PINs exist elsewhere in this app. Sharper than a gap —
   this reintroduces a single point of coercion Shamir's own design eliminates (no party, including a
   coerced owner, can reconstruct alone; recovery needs `threshold` *independent* trustees). Before this
   feature, a coercer holding the owner and the file still needs to separately reach several trustees.
   After, if they can also compel the passphrase, they don't. **Accepted, not fixed** — a duress
   variant (a second passphrase opening a decoy/empty result, mirroring duress PINs) was considered and
   explicitly not built here; real design work on its own, out of scope for this decision. Document the
   boundary plainly wherever this ships in-app: protects opportunistic and third-party exposure, not a
   detained-owner scenario.

   **Word selection: auto-generate by default; at most one word swappable via search.** Full free
   choice for every word was considered and rejected — human-chosen "memorable" words are well-
   documented to cluster far from uniform, materially cutting the effective entropy this whole decision
   rests on. Bounding a swap to one word caps the cost at that one word's ~13 bits rather than losing
   most of the passphrase's strength to predictability.

   **Two implementation constraints, found 2026-09-06 during review — both are precedent, not new
   ground.** Neither is optional if this ships:
   - **The word-search field needs `.autocorrectionDisabled()` and `.textInputAutocapitalization(.never)`.**
     Without them, a searched-but-not-chosen word still lands in the system keyboard's dynamic-text
     dictionary — outside this app's storage, outside its threat model, permanently — exactly F1's
     finding (`Docs/Audit/OPEN_LIMITATIONS.md`) for vault entry content, applied to a new field that
     didn't exist when F1 was fixed.
   - **Any "copy passphrase" convenience must go through `UIPasteboard.copySensitive`, never
     `UIPasteboard.general.string =` directly.** F2's exact fix — `.localOnly` plus a 120s expiry —
     exists because one call site got the bare setter wrong once already; this is a new call site for
     the identical class of secret.

   **Minor, pre-existing, non-blocking:** `generate()`'s `randomValue % 7776` carries the same shape of
   modular bias already tracked and rated negligible elsewhere in this codebase (Bug 72, ~3.7×10⁻⁹) —
   different function, same class of issue, worth a one-line note if touched, not a blocker here.

   **Not yet implemented.** Decided, not built. This half touches `RECOVERY_BUFFER_LAYERING.md`'s
   territory (the exported/pending backup contents), not this container.

5. **File-identity architecture — settled 2026-09-06: one shared pool, generalized beyond the original
   framing.** §5's "Where it lives" traced the existing contact-blob backend
   (`AppGroupLayerStoreBackend.swift`) and found it already avoids magic bytes and fixed filenames, but
   still uses a purpose-named dedicated directory (`"blobs"`) — a residual signal once a second and
   third differently-purposed container exist alongside it: an examiner who's read this app's source
   learns "a concealment subsystem lives here" from directory structure alone, before touching a byte,
   and with multiple purpose-named directories, learns roughly how many subsystems exist. Worse than a
   passive gap — it lets a coercer target compulsion precisely ("this exact file is your recovery-key
   container, give us that key specifically") instead of only being able to demand a key for an
   undifferentiated pile of look-alike files.

   **Decision: one shared, undifferentiated pool for every internal concealment container** — same
   naming/renaming-on-every-write/size convention, disambiguated purely by which of the app's own keys
   successfully opens a given file (`AES.GCM.open`'s own authentication failure standing in for a magic
   byte, for free; no new primitive needed). Cost is a handful of trial decryptions per lookup —
   trivial for a fixed, small key set.

   **Generalized further than the original A/B framing: one pool, not split by key domain.** No
   security reason to keep biometric (vault key) and non-biometric (Secure-Mode, recovery-buffer)
   containers in separate pools — protection comes entirely from the key, not the filesystem location,
   and splitting by domain would just reintroduce a smaller version of the same signal this decision
   removes. Fewer distinguishable groupings is strictly better.

   **The existing, already-shipped contact blob migrates into the pool too**, not just the two new
   containers — the one real cost beyond what was originally scoped. A one-time migration step
   alongside Stage 1's other migration work: move the blob out of its current dedicated `"blobs"`
   directory into the shared pool under the new naming convention. No special tombstoning needed for
   the vacated directory — consistent with the earlier finding that app-update filesystem changes
   aren't something this project's threat model defends against (no assumed before/after snapshot
   comparison capability).

   **Exported `.occbak` files stay out of the pool, deliberately.** These are a different kind of
   object — user-visible, meant to leave the device via a document picker — not hidden, device-resident
   state. Folding them in would blur a distinction that's load-bearing: `B4`'s strategy depends on an
   internal blob being indistinguishable *from* an ordinary export, which requires them to remain
   separate artifacts that happen to look similar, not the same storage.

   **Dependency, not a blocker on this decision:** `RECOVERY_BUFFER_LAYERING.md`'s own "where it lives"
   needs to adopt this same pool for the property to close completely — a container left in its own
   separate directory while everything else shares a pool just relocates the signal. Not yet applied
   there; picks up whenever that document's storage section is next touched.

   **Not yet implemented.** Decided, not built.

6. **Item 4's live-slot fix does not cover vault entries — found 2026-09-06, decided 2026-09-06.
   Superseded 2026-09-09 by item 11 — not built, `entriesSlotKey` dropped in favor of the same
   full-array-reseal/code-discipline posture item 7 already settled on for the BEK field. Preserved
   below for the record.** §4
   describes the threat as a coercer with the vault key decrypting *every slot*, "including
   `shardMetadata` — trustee counts and identities." Item 4's remedy is titled and scoped to "the BEK
   field's slot separation," and its `slotKey(depth)` formula is applied only to the BEK record. But
   §5.1's target design has **two** separately-sealed fields per slot — the BEK record and sensitive
   vault entries — and the same vault key opens both. Once S8 is built, a coercer holding the vault key
   can still decrypt every other depth's vault entries — seed phrases, key tokens, notes, the most
   sensitive content in the app — by the identical mechanism item 4 was supposed to close. The fix
   landed on the less sensitive of the two fields sharing the container.

   **Resolution: the identical mechanism, own domain-separated key.**
   `entriesSlotKey(depth) = HKDF(inputKeyMaterial: vaultKey, info: "vault-entries-slot" ∥ depth ∥
   pin(depth))` — same shape as item 4's `slotKey`, different `info` string. Not a shortcut: two
   separately-sealed fields get two separately-derived keys, the same domain-separation discipline
   already used elsewhere (`K3`: distinct `info` strings for the blob key and PIN verifier keys
   specifically so a compromise of one says nothing about the other). One shared key protecting both
   fields would fail that standard.

   **The frequency question this raises that item 4 didn't have to answer.** The BEK record is read
   rarely — setup, distribute, export, restore. Vault entries are read constantly — every Vault tab
   open, every entry displayed. Deriving from the raw PIN on every read would either force re-deriving
   from PIN each time or force retaining the raw PIN in memory for the session, itself a new exposure.
   Resolution: derive `entriesSlotKey` once, at the moment the depth's own PIN is verified to reach
   that depth, and cache the *derived key* — never the raw PIN — for the scene-phase duration, cleared
   on background. Identical shape to **C2**'s existing cache for the hybrid local DB key
   (`Manager.Key`), not a new caching concept. Architecturally sound because reaching any depth already
   requires that depth's PIN entry first — there is no path to vault entries that skips it, so the PIN
   is always available at the exact moment this derivation needs it.

   **Not yet implemented — and now won't be, as designed above.** Superseded 2026-09-09 by item 11:
   `entriesSlotKey`, needing that depth's own PIN to derive, cannot be resealed by any other depth's
   session — the identical structural conflict with full-array reseal that item 7 found for item 4's
   `slotKey` one day after this item proposed the same shape for a second field. Kept only as a record
   of what was considered and why it was set aside.

7. **Per-slot write pattern leaks which depth is active, across snapshots — found 2026-09-07, settled
   2026-09-07: accept the risk, matching Bug 106's precedent. Item 4's live-slot `slotKey` is
   superseded — not built.**

   **The mechanism.** Each of the 32 BEK slots is independently AES-GCM sealed (own nonce, own tag,
   `BEKSlotAAD`-bound). Writing depth N's slot was planned as: leave every other slot's ciphertext
   byte-for-byte untouched, replace only slot N's, write the whole file out under a fresh filename. The
   filename is randomized (uninformative), but the *other 31 slots' bytes are copied verbatim*. An
   adversary holding two snapshots of this file from different points in time can diff them with no key
   at all: 31 slots identical, one different, directly identifies which depth is actively used.

   **Correction, found while assessing this: the file is already backup-excluded, same as
   `SecureMode+LayerStoreBackend.swift` (`isExcludedFromBackup = true`).** The original write-up cited
   Bug 101 as evidence this threat is already live — wrong; Bug 101 is about unmanaged
   `Documents/Inbox` files, a completely different, unprotected category. This file, like the contact
   blob, is never in an iCloud or iTunes backup. The realistic path to two snapshots is physically
   re-imaging the same device on separate occasions — a narrower adversary (repeated forensic custody,
   or a sustained-access domestic threat) than routine backup exposure. This narrowed threat is part of
   why accepting the risk below is defensible, not just expedient.

   **Decision: accept the cross-depth-reach risk, drop item 4's live-slot `slotKey`, reseal all 32
   slots with fresh nonces on every write.** Matches `Manager.LayerStore`'s existing, shipped posture
   for contacts exactly — one key for every slot, full-array nonce refresh closes the snapshot-diffing
   leak completely and *permanently*, with no future collision to reconcile, because there is no
   `slotKey` for it to collide with. This is Bug 106's own precedent, now deliberately extended to BEK
   rather than left as a coincidence: contacts already carry this same trade-off in shipped code, and
   the same call is made here for consistency, weighed against the corrected, narrower threat above.
   Item 4's live-slot cryptographic isolation is superseded, not implemented — the vault-key-extraction
   risk it targeted stays at code-discipline separation, the same posture Bug 106 already documents for
   `LayerStore`. Item 4's *other* half (the exported `.occbak` 6-word passphrase) is unaffected — a
   separate mechanism, not touched by this.

   **What this changes structurally:** the BEK array's write path always reseals all 32 slots on every
   write, not just the touched one — a real, necessary revision to the backend design discussed
   earlier, not an optional hardening. `BEKPayloadCodec` and `BEKSlotAAD` are both unaffected — per-slot
   AAD binding still matters (it's what stops a slot-swap attack; full-array resealing stops the
   snapshot-diffing one, a different property).

   **Also applies to `RECOVERY_BUFFER_LAYERING.md`'s own eventual per-slot backend** — flagged there for
   whoever picks up that container's backend, not analyzed here. That container was never going to face
   item 4's specific collision (its key isn't depth-derived today), but the underlying write pattern
   still needs the same full-array-refresh treatment for the identical reason.

8. **Findings from starting the BEK backend build, 2026-09-07/08 — two documented and still open, one
   found and fixed in a security/forensic review before any backend code was written.**

   **`AppGroupLayerStoreBackend.findFile()` doesn't implement the disambiguation item 5 promised, and
   the shared pool would break the shipped contact blob if used as designed today.** `findFile()`
   (`SecureMode+LayerStoreBackend.swift:90-102`) selects by newest-modification-date among files with
   the `.occbak` extension — it never tries opening candidates with a key at all. That's correct for
   exactly one file in the directory, which is all that exists today. The moment the new BEK array file
   joins the same `"blobs"` directory under the same extension (item 5's design), `findFile()` would
   nondeterministically return whichever file was written most recently — not necessarily the caller's
   own file. A write to the BEK array after the contact blob would make the *contact blob's own
   `read()`* silently start returning BEK bytes. This is not a hypothetical edge case; it's how the
   function is written today. **Item 5's "disambiguated by which key opens it" was never actually
   implemented** — the real selection logic needs rewriting to try each candidate file against the
   caller's own key/AAD and use whichever succeeds, which means touching existing, shipped production
   code (the contact blob's own backend), not just adding a new one alongside it.

   **Decided 2026-09-08: the BEK array uses its own directory for now, not the shared `"blobs"`
   directory.** Keeps the fix surgical — new file, no touching shipped contact-blob code in the same
   change — at a real, accepted cost: a second directory reintroduces a milder version of the exact
   signal item 5 was built to eliminate (an examiner sees two purpose-differentiated directories
   instead of one, even if neither name says what it holds). This is explicitly interim, not a revised
   architecture — item 5's shared-pool decision is unchanged; `findFile()`'s fix and the directory merge
   are deferred, separate work, not abandoned.

   **Migration carries forward pre-existing Bug 105 poisoning, if any, with no way to detect it.** If a
   device was coerced into distributing shares of the real BEK (Bug 105) *before* ever updating to this
   design, the legacy row's `shardMetadata` already reflects the coercer's trustee list, not the
   owner's — same `bekBytes`, same `distributionID`, no depth stamp anywhere to tell them apart, because
   the pre-fix code never tracked depth at all. Migration (§9) faithfully moves whatever the legacy row
   currently holds into slot 0, so a pre-existing compromise lands in "the real depth's slot" looking
   exactly like a legitimate setup. Not a bug migration introduces — the same ambiguity already exists
   in the single unlayered row today, and migration only relocates it once; every write after migration
   is correctly depth-isolated by Stage 2. Scoped to devices already compromised before they update.
   **Possible mitigation, not yet decided:** prompt the user to review their recovery contacts at the
   same depth-0 session where migration runs, giving a freed, coerced user a chance to notice an
   unrecognized trustee — UX work, not a backend change, not yet scoped or committed to.

   **Third finding, found and fixed 2026-09-08 during a security/forensic review of the codec and the
   backend design, before any backend code existed: the write algorithm as described conflated two
   different failure modes, and the conflation was a real data-loss path.** The design (per-slot: try
   `open` + `decode`, success → real, failure → filler, generate fresh random plaintext) treated
   "`open` succeeds, `decode` fails" and "`open` itself fails" identically. Those are not the same
   thing. The first is genuinely empty — random noise that authenticates under the right key but isn't
   structured content, safe to treat as absent. The second means the ciphertext doesn't authenticate at
   all under the correct key and AAD, which should essentially never happen for a slot this backend
   itself wrote — it means disk corruption, a partial write from a crash, or a bug. Treating it as
   "empty" would silently overwrite a slot that was real but transiently unreadable with random garbage
   on the very next write, with no error and nothing recoverable — the same failure shape
   `Docs/Audit/OPEN_LIMITATIONS.md` C1 names elsewhere in this codebase ("wrong-key ciphertext...
   indistinguishable from an empty field... the direct reason Bugs 75-78, 80 were silent permanent data
   loss"), reproduced fresh in a brand-new subsystem before it shipped.

   **Fix, folded into the design directly: `open` failure throws and halts the write; only
   `open`-succeeds-`decode`-fails counts as empty.** Consistent with how file identification already
   has to work (trying slot 0's `open` alone, independent of whether `decode` then succeeds) — the write
   algorithm was the one place this distinction wasn't being honored. Noted separately: the existing,
   shipped `AppGroupLayerStoreBackend.write()` doesn't use `.atomic` in its write options, only
   `.completeFileProtection` (a Data Protection class, not an atomicity guarantee) — a crash mid-write
   could leave a corrupted file today. Pre-existing, not introduced here, but it's the concrete scenario
   this fix has to handle correctly rather than silently paper over.

   **Two smaller fixes to `BEKPayloadCodec`, same review pass, already applied:** `decodeV1` extracted
   `bekBytes` into a local buffer with no `defer` zeroing, unlike every other BEK-handling function in
   this file and the file's own stated convention — fixed, the working `[UInt8]` copy is now zeroed on
   return. Separately, the function mixed two indexing idioms (`[UInt8](data)`, which always rebases to
   0, and `data.subdata(in:)`, which doesn't) — harmless today given real callers always pass
   freshly-decrypted `Data`, but latent, and worth closing before the backend starts slicing real file
   contents. Both fixed by slicing consistently from the already-rebased array.

9. **Stage 2 design correction, found 2026-09-08: `reconstructBEK` must be depth-routed, not pinned to
   depth 0 — my own first proposal for this got it backwards, and it's blocked on
   `RECOVERY_BUFFER_LAYERING.md`'s own not-yet-built work, not just on this document.**

   **The mistake.** Scoping Stage 2, `reconstructBEK` was proposed to keep completing only at depth 0,
   with an internal precondition enforcing it — carrying forward Bug 93's existing
   `attemptBEKRestore` guard (`currentDepth == 0`) as if it were still correct once every depth has its
   own independent BEK. It directly contradicts this document's own acceptance criterion, stated above
   in §7: *"a coercer can arm, set up his own trustees, collect and complete a restore in his layer...
   because it is a working app in that layer, not a simulation of one."* Restore pinned to depth 0
   means a coercer's own duress-depth restore can never complete, no matter what he does.

   **Why that's a real, sharper oracle than the one Bug 93 already closed.** Bug 93's fix defends
   against a *comparative* oracle — depth 0 looking different from a duress depth to someone who can
   observe both, or who knows the app's design. It does not defend against a coercer who supplies his
   *own* trustees, sends threshold-many shares back to himself from phones he controls, and watches
   nothing happen. He needs no comparison to depth 0 for this to be informative — he has independent,
   self-verified ground truth (he knows exactly what he sent), and "nothing completes, ever, no matter
   what" directly contradicts the app's own stated mechanism (threshold shares reconstruct the key).
   This is Bug 99's exact pattern: *"a coercer who supplies his own trustees can test whether the phone
   is in duress, because a restore completes in one layer and not the other."*

   **Why "depth 0 only" was correct before Stage 2 and wrong after.** Pre-refactor there is exactly one
   device-wide BEK — letting restore complete anywhere risks exposing the real vault at a duress depth
   (Bug 93 harm 2). Once each depth has its own independent BEK, own trustees, own slot, a coercer's
   restore-to-himself reconstructs *that depth's own* key and recovers *that depth's own*
   already-visible content — nothing left to protect by blocking it. The old rule solved a problem
   Stage 2 itself removes; keeping it stops solving anything and starts creating the oracle above.

   **The actual blocker, found checking `refreshPendingRestoreState`/`storePendingRestore`: they and
   the files they read are single, device-wide artifacts, not slotted per depth at all.**
   `storePendingRestore` refuses a second file with `alreadyProcessed` if *any* restore is pending,
   checked against one shared file (`backup-import-cache.occbak`) regardless of depth — there is no
   "depth 0's pending restore" versus "depth 2's own," only one, device-wide. A depth-routed
   `reconstructBEK` has nothing per-depth to read arming/shard-buffer state from yet. That work belongs
   to `RECOVERY_BUFFER_LAYERING.md`, not here — its own Stage 4 ("per-depth restore state: arming,
   sealed backup contents, shard buffer, per-depth cancel") is exactly this, and its Stage 5
   ("completion per layer") is the explicit join point that reads collected shares from that container
   and writes the reconstructed BEK into this one's slot. Neither has started. So: this container's own
   Stage 2 (routing the BEK array itself by depth — `fetchDecodedBEK`, `setupBEK`, `currentBEK`,
   `bekShardMetadata`, `prepareBEKShards`, `distributeBEKShards`, `rotateBEK`, `updateBEKShardStatus`)
   is unaffected by this and can proceed independently; the `reconstructBEK`/restore-completion piece
   specifically cannot be finished correctly until the sibling document's per-depth restore state
   exists.

   **A correction to my own understanding, found in the same pass, not a new decision:** Bug 93's
   original "hide pending-restore state above depth 0" has already been reversed in shipped code —
   `refreshPendingRestoreState`'s own doc comment states it plainly: *"Publishing the same state at
   every depth removes the comparison... Hiding was closing a duress-against-duress gap and opening a
   duress-against-real one."* I was reasoning from `bugs.md`'s original Bug 93 writeup instead of
   checking the current code first, and stated the old, already-superseded behavior as if it were
   current. The completion guard (`currentDepth == 0`) is the only piece of the original fix still in
   place — and per this item, that piece needs to change too, not stay as precedent.

   **Not resolved.** Cross-container work needed before `reconstructBEK`/restore-completion can be
   built correctly. See `RECOVERY_BUFFER_LAYERING.md` for the other half.

10. **Stage 2's array-routing half built 2026-09-08. `updateBEKShardStatus` deliberately takes no
    `currentDepth` — found, while wiring it in, that "whatever depth is current" is not a reliable way
    to find which slot owns a given trustee confirmation, even outside the async/queued case.**

    Every other Stage 2 function (`fetchDecodedBEK`, `persistBEKPayload`, `setupBEK`, `currentBEK`,
    `bekSetupState`, `bekShardMetadata`, `prepareBEKShards`, `distributeBEKShards`, `rotateBEK`,
    `exportBackup`, `refreshBackupStaleness`) took a `currentDepth: Int` parameter with no default,
    matching the project's established "a forgotten argument must be a compile error" convention.
    `updateBEKShardStatus` was drafted the same way at first.

    **Why that was wrong.** `updateBEKShardStatus` is reached two ways: directly, when a trustee's
    confirmation manifest arrives while the vault is unlocked (`ShardCustody+Manager.swift`'s
    `processInboundManifest`, via `VaultManager.updateShardStatus`'s BEK fallback); or queued as a
    `PendingShardStatusUpdate` row and replayed by `drainPendingShardStatusUpdates()` on the next
    `unlock()`, if the vault was locked when the confirmation arrived. The queued path obviously can't
    use "current depth" — it wasn't unlocked at all when the update was queued. But the direct path is
    just as unreliable: a shard gets distributed from depth 0, the owner later switches to a different
    depth for an unrelated reason, and *then* the trustee's confirmation arrives while depth 0 is no
    longer active. Using `currentDepth` to pick which slot to search would silently miss it in both
    cases — not a rare edge case, just how asynchronous confirmations actually arrive.

    **The fix.** Removed the parameter. `updateBEKShardStatus(attributeID:to:)` now loops over
    `BEKSlotAAD.validRange` (all 32 slots), using `try?` to skip any slot that fails to open or doesn't
    decode as having `shardMetadata` — both mean "not the one being searched for," not corruption.
    Once the slot whose `shardMetadata.shards` actually contains the `attributeID` is found, the status
    transition is applied there and `persistBEKPayload` is called with that discovered depth. This
    needs nothing beyond the vault key already being available: `vaultKey` itself isn't depth-derived —
    only `BEKSlotAAD`'s AAD provides per-slot binding — so trying all 32 slots costs up to 32 slot
    reads, only on this comparatively rare, per-confirmation path, not a hot path. An `attributeID` is
    structurally guaranteed to belong to exactly one depth's `shardMetadata` (a fresh `UUID()` per
    shard per `prepareBEKShards` call), so the search either finds one match or none. One fix serves
    both the immediate and the queued/deferred case — there was never a reason for two.

    **A second gap found bringing the rest of the target up to date, same pass: `recomputeRecoveryHealth`
    had to lose its `bekErosion` half too, for the identical reason.** It's called both from `unlock()`
    (which has `currentDepth` in scope) and automatically from a `ModelContext.didSave` subscriber
    (`Vault+Manager.swift`, no depth in scope at all — an unrelated save anywhere in the app can fire
    it). `bekErosion`, once BEK became per-depth-slotted, needs a depth to read the right slot; defaulting
    the auto-triggered path to any fixed depth would silently repaint the UI's erosion display for the
    *wrong* depth on an unrelated save — e.g. surfacing the real (depth-0) BEK's erosion state while the
    user is in a duress layer, a coercer-observable leak of exactly the kind this document's threat
    model exists to prevent. Fixed by splitting `bekErosion` into its own `refreshBekErosion
    (currentDepth:)`, following the precedent already set by `backupStaleness`: refreshed only by the
    views that display it (`Vault+Tab`, `VaultRecoverySettings`, both with `Manager.Security` in scope),
    not from any auto-triggered or depth-blind path. `recomputeRecoveryHealth` itself keeps the PEK half
    (not depth-scoped) and stays on the auto-save trigger unchanged.

    **A third, smaller consequence surfaced fixing the build: `exportBackup(currentDepth:)` now
    genuinely requires *that* depth's own BEK to be configured, not just depth 0's — this is Stage 2
    working as intended, not a bug, but it meant two pre-existing tests
    (`VaultBackupRoundTripTests.exportExcludesHiddenEntries`, `.stalenessIsIsolatedPerDepth`) needed
    their fixtures updated to set up a confirmed BEK at depth 2 before exporting at depth 2, since they
    predate BEK becoming per-depth-slotted and previously relied on every depth sharing the one
    device-wide BEK row.** Extracted the shared setup into `setUpConfirmedBEK(for:in:currentDepth:)` so
    both tests (and any future one needing a second depth's BEK) call it rather than duplicating
    `makeBackupReadyVault()`'s inline setup a third time.

    Tests: `shardConfirmationAppliesToOwningDepthOnly` (`VaultBackupRoundTripTests.swift`) — sets up a
    pending (unconfirmed) shard pair at depth 2 alongside depth 0's already-confirmed pair, confirms one
    of depth 2's shards, and asserts depth 0's shards are untouched and depth 2's *other* shard is still
    pending — proving the search finds the right slot and disturbs nothing else. Full BEK-related suite
    (`BEKPayloadCodecTests`, `BEKSlotAADTests`, `BEKArrayTests`, `VaultBackupRoundTripTests`,
    `VaultRestoreTrustTests`, `VaultRestoreRobustnessTests`, `RotationRegistryTests`) re-run clean after.

11. **Item 6 and item 7 are mutually exclusive, not just in tension — found 2026-09-09. `entriesSlotKey`
    is dropped; vault entries get item 7's exact key posture instead: plain `vaultKey`, full-array
    reseal, code-discipline-only separation. Revised the same day, before anything was built against
    it: §5's "one array, two fields per slot" is reopened too — vault entries get their own array, not
    a shared slot with BEK.**

    **Why `entriesSlotKey` and full-array reseal can't both hold — the same structural proof item 7
    already gave for `slotKey`, one day earlier, for a different field.** `entriesSlotKey(depth)` needs
    that depth's own PIN to derive. A session at depth 2 holds only depth 2's PIN — never depth 0's, by
    the same design that made item 4's `slotKey` attractive in the first place. Item 7's full-array
    reseal requires opening and re-sealing *every* slot's plaintext on every write, which requires
    holding every depth's key. A depth-2 session can never compute `entriesSlotKey(0)`, so it can never
    reseal depth 0's vault-entries field under a fresh nonce. Item 6 proposed `entriesSlotKey` using the
    identical fold-the-PIN-into-`info` shape as item 4's `slotKey`, decided 2026-09-06 — one day before
    item 7 found that exact shape incompatible with full-array reseal for the BEK field. Item 6 was
    never revisited against it. **This part stands: plain `vaultKey`, no per-depth key, no per-depth
    cache to build.**

    **What didn't hold up: the first attempt at fitting vault entries into §5's one-array design.**
    Two shapes were tried, in order, both before any code existed against either:

    - *Two independently-sealed fields per slot* (the original version of this item) — scope the reseal
      to just the touched field, leaving BEK's ciphertext untouched on an entries-only write. This needs
      the two ciphertexts to be unswappable, which `BEKSlotAAD`'s existing slot-index-only AAD doesn't
      provide once two fields share one slot — a real, then-uncovered gap, closed only by adding a new
      field-type AAD binding.
    - *One combined seal per slot* — no new AAD needed at all (one AEAD tag authenticates the whole
      slot atomically, nothing to swap out of it), but any write to either field now reseals both,
      and `BEKPayloadCodec` would either have to grow vault-entries fields into a type whose entire
      name and identity is the Backup Encryption Key's wire format, or a new wrapper codec would have
      to compose it with a second, new codec — real new code either way.

    **Then a sharper question dissolved most of the reason to combine them at all.** Full-array reseal
    already hides *which depth* changed, identically, whether the touched field lives in one file or
    two — an examiner diffing two snapshots of two independently-resealed files sees the same "31
    identical, one different" pattern in each, uninformative about depth either way; nothing about that
    property requires the two fields to share a slot. What one array *did* still buy over two was
    hiding *that a BEK operation happened rather than an entries operation* (or vice versa) from an
    examiner comparing the two files' mtimes — but this item's own reasoning already ruled that outside
    item 7's threat model (hides depth, not operation kind) before the AAD gap was ever found. Once
    that's granted, two independently-resealed arrays lose nothing item 7 or this item actually
    requires.

    **What's left of "one array is fewer artifacts to explain" (§5) is real, but narrower and more
    temporary than it reads.** One fewer enumerable file today — but the BEK array already lives in its
    *own* directory, not the shared pool (item 8), specifically because item 8's `findFile()` fix is
    still deferred. Item 8 already named and accepted this exact cost once, for that directory: *"a
    second directory reintroduces a milder version of the exact signal item 5 was built to eliminate...
    explicitly interim, not a revised architecture."* A second directory for vault entries is the same
    class of cost, not a new one, and it disappears entirely once the shared-pool merge lands — at that
    point file count stops being a meaningful signal regardless of how many purpose-differentiated files
    the pool holds.

    **Weighed against two costs combining pays permanently, not just until the pool merges:**
    corruption blast radius — one corrupted slot loses the BEK record *and* the vault content for that
    depth together, no independent failure, when BEK is separately reconstructable from trustees and
    vault content generally isn't; and code cost — a combined design needs new composition machinery
    (`BEKPayloadCodec` unchanged plus one of the two shapes above) that two independent arrays don't,
    because they can each just be `BEKArray`'s already-shipped, already-tested shape, cloned.

    **Resolution: two independent arrays, not one.** Vault entries get their own array, own backend
    instance, own codec, own AAD — each mirroring the BEK chain's exact, already-proven shape rather
    than composing with it:

    | BEK (unchanged) | Vault entries (new, provisional names) |
    |---|---|
    | `BEKArray` | `VaultEntriesArray` |
    | `BEKPayloadCodec` — fixed 10,761 B | `VaultEntriesPayloadCodec` — dynamic, item 2's format |
    | `BEKSlotAAD` — `"occulta-bek-slot-v1"` | `VaultEntriesSlotAAD` — own domain string, same shape, reuses `BEKSlotAAD.slotCount`/`validRange` rather than redefining 32 a second time |
    | `AppGroupBEKArrayBackend` | a second file, own directory — the backend protocol is already payload-agnostic; needs its hardcoded directory constant made configurable (or a sibling instance), a mechanical change, not a design one |

    `BEKArray`, `BEKPayloadCodec`, `BEKSlotAAD`, `AppGroupBEKArrayBackend` are all untouched by this —
    zero changes to shipped, tested Stage 1 code. `VaultEntriesSlotAAD` needs its own domain string,
    not a shared one with `BEKSlotAAD`, even across two files: reusing the exact same AAD for two files
    sealed under the same `vaultKey` would let a slot-N ciphertext from one file authenticate if pasted
    into the other file's slot N — the same cross-container reuse `BEKSlotAAD`'s own domain separation
    already exists to prevent, one level up.

    **§5's "one fixed-width array... two separately sealed fields per slot" is superseded by this item
    — preserved there for the record, not a live description of the target design anymore.**

    **Not yet implemented.** Decided, not built. Blocks nothing today — S8 isn't built yet — but must
    ship alongside it, not be discovered as a gap after.

12. **Contacts' Design B — the four steps S8 is meant to reuse — has no fifth step for persisting a
    mid-session edit. Found 2026-09-09 while checking whether S8 could safely copy them as-is; the gap
    is actually in `forensic-trace-avoidance.md`/`plan.md`'s territory, not this document's, but S8
    inherits it directly.**

    The four named steps (activation: shell the DB, snapshot to blob; unlock: load blob into an
    in-memory array; lock: wipe that array; display: merge DB + in-memory) cover activation and the
    unlock/lock boundary. None of them writes an edit made *during* the unlocked session back to the
    blob. Checked directly, not assumed: `Manager.LayerStore.push()` — the only call that writes real
    content — has exactly two call sites in the whole codebase, both one-time (activation's snapshot;
    a decoy write on PIN collision). `rewrite()` doesn't refresh content either — it overwrites all 32
    slots with random junk, a wipe. Under Design A this is harmless, because the DB row stays the live,
    authoritative copy for the session and the blob is just a periodic snapshot. Under Design B it
    isn't: the DB row goes cryptographically dead at activation, so an edit that lives only in the
    in-memory array is lost the moment the process backgrounds or is killed, not just hidden.

    **Why this belongs here even though it's Design B's gap, not this container's.** The release
    owner's candidates decision (below) has S8 reuse Design B's lifecycle "once built once on the
    cheaper case" — literally the same four steps, applied to vault entries instead of contacts.
    Copying them as specified would copy the missing fifth step too, and vault entries are edited far
    more often than sensitive contacts, so the exposure window is proportionally worse here than where
    the gap was actually found.

    **Designed, not built — 2026-09-09, same day.** `plan.md`'s "What Design B requires" list, item 4
    has the full finding, item 5 has the fifth step: reuse `push()` itself on every mutation to
    `inMemorySensitiveContacts`, reusing the depth's on-record `slotIndex`/`sequenceNumber` rather than
    regenerating either — regenerating the sequence number would silently break every later `pop()` at
    deactivation, caught before proposing it. Surfaced a co-requisite: step 2's own non-destructive read
    (`readPayload`) is currently commented test/diagnostic-only, not a sanctioned production path.
    Neither S5 nor S8 is safe to build until this is. Cross-referenced from `forensic-trace-avoidance.md`
    S5 too, and filed as `bugs.md` Bug 108.

**Vault entries and contacts (S5/S8) — candidates, decided 2026-09-02 by the release owner:** build
both, S5 (contacts) before S8 (vault entries). Contacts' Design B is already specified and deferred —
unreadable shells in the DB, existing `LayerStore` blob is the canonical copy, loaded to memory on
unlock, wiped on lock — no new file or key, four named steps. Vault entries reuse the identical
lifecycle in this container instead of the existing one, once built once on the cheaper case. §4a
stayed unverified throughout and was not the basis for this decision.

**Accepted limitation, found and closed out 2026-09-07: an empty or sparse duress-depth vault is
directly visible to a coercer who compels live authentication — cold-storage padding doesn't reach
that scenario.** Narrowed on examination to two specific, non-default conditions (coercer has prior
knowledge of expected content; coercer compels and compares multiple depths) rather than a general
risk. Full reasoning and disposition in `Docs/Audit/OPEN_LIMITATIONS.md` §I.

---

## 9. Migration and release scope

Settled 2026-08-28. **Release target superseded 2026-09-07** — see the correction below; the
compatibility and tombstoning reasoning that follows is unaffected by which branch ships it.

**Release scope, as originally settled.** Ships in **v1.10.3**, branch `v1.10.3/bek-layering-refactor`
off `release/v1.10.3` — not a separate `develop` branch, since `develop` was 133 commits behind at the
time and would have dropped every fix this design builds on. (Both branches have since merged; no
longer diverging.) The patch framing is deliberate: Bug 105 is live, and its standalone remedy is the
unattractive one in §6. Cost: a patch version implies downgrade is safe, and after this migration it is
not.

**Correction, 2026-09-07: that release has already happened, without this fix.**
`v1.10.3/bek-layering-refactor` merged into `release/v1.10.3` — but only design consolidation and bug
filing, not Stages 1-2's actual implementation — and `release/v1.10.3` has since shipped with Bug 105
still open. The scope described above no longer has a live release to land in; the fix now targets the
current branch, `v1.11.0/vault-key-layering` off `release/v1.11.0`. The "patch implies downgrade-safe"
cost noted above still applies to whichever release actually ships it — that constraint is about the
migration's own shape, not the specific version number.

**Compatibility.** New build reads old data — free, `BackupEncryptionKey.Payload` is `Codable`, fields
added as optional decode against existing ciphertext untouched. Old build reads what the new build
wrote — impossible for slot 0 by construction; an old build only keeps working if the device-wide row
still holds the real key, which is Bug 105 itself. The conflict is narrowed to only slot 0's BEK bytes
— everything else (sibling files, the visibility gate, the cap) is additive and downgrade-tolerant.
**Add a `formatVersion` byte** to the new file's sealed plaintext — `ExportMetaSlotCodec` has none, a
gap worth not repeating.

**Tombstone the legacy row — do not delete it.** When slot 0's BEK moves into the slot file, keep the
`BackupEncryptionKey` row and overwrite `encryptedPayload` with same-length filler. Deleting it is
itself a new tell. A filler-filled row is indistinguishable from a real one on cold disk. More
importantly, a downgraded build then fails closed at three of four sites (`setupBEK` no-ops on row
presence; `currentBEK` throws; `reconstructBEK` propagates decrypt failure) — the fourth,
`storePendingRestore`, is the soft spot tracked in `RECOVERY_BUFFER_LAYERING.md` §6 item 8, since
arming a restore is that container's action even though the check reads this container's tombstoned
row.

**Rejected alternatives:** dual-run (legacy restores finish under legacy rules) — attacker-pinnable, a
coercer who arms before updating keeps every pre-design weakness; complete-then-migrate — strictly
worse, gated on an event a coercer can indefinitely prevent (Bug 99); keep depth 0's BEK in the legacy
row, slot only depths ≥1 — genuine downgrade safety, but reintroduces the "slot count must never vary"
leak in a different shape.

**Two Stage 1 implementation questions, settled 2026-09-07:**

**Fixed-width wire format ships as part of Stage 1, not after it.** Item 3 already established that
its wire format changes `Payload`'s encoding project-wide, not just `shardMetadata`. Building Stage 1's
new sealed file with today's `JSONEncoder()`/`JSONDecoder()` (`Vault+Manager+Backup.swift:1016`/1009)
and redoing it immediately after would mean building the same file's format twice, and would expose the
exact JSON-length leak this whole design has fought elsewhere — on a brand-new file, not a legacy one
with an excuse. No real cost identified to building it right the first time.

**Migration timing: first vault unlock after update, at any depth — not gated to depth 0.** Two
things are getting conflated in "seeded with filler at first launch": creating the 32-slot file (pure
random-sized filler, no key needed) can and should happen eagerly at launch, matching the existing
`LayerStore` convention. Migrating the *legacy row's real BEK bytes* into slot 0 is different — it
needs `vaultKey` (biometric-gated), so it can't run before first unlock. The question is which unlock.
`RECOVERY_BUFFER_LAYERING.md` §8 gates its own in-flight-restore adoption to "first depth-0 unlock,"
but that data is inherently depth-0-scoped by construction (a legacy pending restore is depth-0-destined
already). The legacy BEK row isn't analogous — it's device-wide and depth-agnostic until migration
*assigns* it to slot 0, and Stage 1 deliberately defers item 4's depth-derived `slotKey`, so plain
`vaultKey` is available at any depth once biometric succeeds. Gating migration to depth-0-only would
leave Bug 105's exposure window open indefinitely for a session that happens to operate mostly at a
duress depth after updating — undermining the urgency that put Stage 1 first in the first place. Running
unconditionally on first unlock, whatever depth that happens to be, closes the window as early as
possible and creates no depth-conditional signal: the migration check doesn't consult `currentDepth` to
decide whether to run, so a coercer sees identical first-unlock behavior regardless of which depth they
forced their way into (the same "every layer behaves identically" property Bug 99's pattern requires
elsewhere in this design).

---

## 10. Known bugs — this container's

Scoped view into `Docs/Features/Secure Mode/bugs.md`; that file stays canonical for full reasoning.
`RECOVERY_BUFFER_LAYERING.md` §7 carries its own container's bugs — not repeated here.

| Bug | What | Status |
|---|---|---|
| 92 | A backup file is readable from any layer (offline half) | open — complementary to this design, see §4 and §8 item 4 |
| 102 | The BEK has no layer concept | **this document** |
| 108 | Design B has no mid-session edit persistence — contacts' bug, blocks S8 here too | not a live bug, design gap — see §8 item 12 |
| 105 | A duress layer can distribute shares of the real BEK | open — §6; closes via Stage 1+2 |
| 88 | Backup ignored `visibleThroughDepth` in both directions | fixed — export/import are depth-scoped |
| 94a | Remedy 2's attestation field unpadded | fixed — every op ships an attestation, real or filler |

Adjacent, not this container's subject, same root cause: Bugs 103/104 (inbound views render a hidden
contact's identity) — closed as duplicates of an accepted limitation, but instances of "the depth
dimension was not applied at the view layer."

---

## 11. Tripwire

`VaultEntryType` has `document` and `photo` **commented out**. The whole fixed-slot design, in both
containers, rests on a vault backup being kilobytes. Enabling either makes the vault bulk data and
invalidates this container's design entirely. That enum is the place to notice, so the constraint
belongs as a comment there too.

---

## See also

[`RECOVERY_BUFFER_LAYERING.md`](RECOVERY_BUFFER_LAYERING.md) — the shard buffer, restore/arming state,
and `CustodyShard`. Independent of this document except at §7 Stage 5 (completion) and that document's
§6 item 8 (the `storePendingRestore` soft spot), both noted at their point of contact above.

[`VAULT_BACKUP_GUIDE.md`](VAULT_BACKUP_GUIDE.md), [`VAULT_SSS_GUIDE.md`](VAULT_SSS_GUIDE.md) — the
spec docs for the behavior this design replaces. Both describe today's device-wide BEK/shard machinery
as shipped; this document is why and how that changes, not a second description of what it does. Keep
their own "Secure Mode" closing sections pointed here as this design's decisions land.

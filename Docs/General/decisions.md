# Decision Log

A scannable index of decisions made across Secure Mode, Vault, and Contacts — separate from
`bugs.md` (defects and their fixes) and the design docs (`VAULT_KEY_LAYERING.md`,
`RECOVERY_BUFFER_LAYERING.md`, `PASSPHRASE_LAYER_KEYS.md`), which carry the full reasoning trail.
Each entry here is a short pointer: what was decided, why, and what it costs — not a replacement
for the design doc section it links to. When a decision is revisited, add a new dated note to the
existing entry rather than rewriting it, matching this codebase's own convention everywhere else.

**When to add an entry:** a choice that (a) closes off an alternative deliberately, not by default,
and (b) would be genuinely useful to find again without re-reading the design doc that produced it.
Not every implementation detail qualifies — most belong only in the design doc or the code comment
next to them.

**Format:** Context (what prompted it) → Decision (stated plainly) → Why (the load-bearing
rationale, condensed) → Consequences (what it costs or gives up) → Full reasoning (where the rest
lives).

---

## Drop every shard operation kind from a sender not visible at the current depth

**Status:** Decided, 2026-09-11. Implemented (`OccultaApp.filterShardOperations`).

**Context:** Stage 3 of `RECOVERY_BUFFER_LAYERING.md` needed to decide what happens when an inbound
shard-protocol bundle (`.distribute`, `.replace`, `.handback`) arrives from a contact hidden at the
current depth — the mechanism that makes per-depth restore attribution correct rather than
dangerous (§2 of that doc).

**Decision:** Drop the *entire* `shardOperations` array — all three kinds, not just `.handback` —
before it ever reaches `ShardCustodyManager`, whenever the sender isn't visible at the current
depth.

**Why:** The scope started narrower (`.handback` only), on the assumption `.distribute`/`.replace`
had no retry mechanism and dropping them risked permanent shard loss. That assumption was wrong,
found while re-checking it: `PendingShardDistribute` persists until the trustee's own
`custodyManifest` confirms receipt — `queueDistribute`'s own doc comment states this directly, and
`processInboundManifest`'s actual code confirms it; the row is never deleted on send.
(`PendingShardDistribute+Model.swift`'s header comment claimed "deleted on send, fire-and-forget" —
stale, corrected 2026-09-12 to match.) Since all three op kinds already retry safely, dropping all
three closes the same "why let a coercer's session write anything at all" concern that motivated
the original ask, with no data-loss cost.

**Consequences:** A coerced session cannot cause *new* custody-shard writes for a hidden owner at
all — not just cannot see them. Pre-existing rows from before the session are unaffected; this is a
write-path filter, not a retroactive scrub. Complements, doesn't substitute for,
`RECOVERY_BUFFER_LAYERING.md` §6 item 7's not-yet-built trustee-depth-keyed storage partitioning.
Placement note: this had to become an instance method on `OccultaApp` rather than a free function or
a static member of it — a `static func` inside the `@main`-attributed `OccultaApp` struct was
invisible to `@testable import Occulta` under this toolchain's explicit-module build, reproduced
consistently; as a consequence, this logic isn't unit-testable in isolation (constructing an
`OccultaApp` instance touches real on-disk storage) and is covered by manual/integration
verification instead.

**Full reasoning:** `RECOVERY_BUFFER_LAYERING.md` §2.1.

---

## Orphan rows in place instead of deleting them, never leaving nil/non-nil as a free signal

**Status:** Decided, first shipped 2026-09-10 (`VaultEntry`), extended 2026-09-11
(`BackupEncryptionKey`); declined for `Contact.Profile` (Bug 112).

**Context:** Depth numbers are reused across unrelated future duress sessions — `deactivateSecureMode`
always returns to depth 0 or 1, and a fresh duress-PIN verification walks back up through 1, 2, 3...
the same way every time. Without a mechanism to invalidate a freed depth's leftover state, a later,
unrelated session reactivating at the same depth number inherits the previous session's vault
entries, contacts, or backup key untouched.

**Decision:** Never hard-delete a row when the depth it belongs to is freed. Instead, flip an
encrypted `deletionToken` field from a fixed-width `liveToken` sentinel to a fixed-width
`orphanedToken` sentinel — never absent, never a plaintext boolean, never nil/non-nil as the signal
— and exclude orphaned rows from every functional read. Row count and existence stay constant
regardless of activity; only the encrypted payload's *meaning* changes.

**Why:** Hard-deleting on deactivation makes row count itself a forensic signal — an examiner
comparing two snapshots sees exactly how many rows a deactivation event removed. Encrypted-but-
present nil/non-nil status is scarcely better: SQLite tracks column nullability structurally,
independent of encryption, so "how many rows are orphaned" is answerable with a plain `SELECT
COUNT(*)` and no key at all (the exact gap Bug 112 named and left open for `Contact.Profile`, judged
not worth its migration cost there). A fixed-width sentinel that's always present closes that for
free everywhere it's used.

**Consequences:** Every functional read of the model must filter on `isOrphaned(usingKey:)` — this
already caused three missed-consumer bugs (110, 113, 115, 116) before every call site was found and
fixed. Rows accumulate forever without a separate cap/eviction mechanism (`VaultEntry`/`Contact.Profile`
cap at 50 with oldest-first eviction — itself not correctly ordered for contacts, Bug 117;
`BackupEncryptionKey` is deliberately uncapped, since BEK rows are created rarely enough that
unbounded growth was judged an acceptable trade against the eviction machinery's own complexity).
For `BackupEncryptionKey` specifically, the *filler* half of the three-state model (filler/live/
orphaned, not just live/orphaned) is what additionally hides row *count* up to a 32-row baseline —
`VaultEntry`/`Contact.Profile` don't have this third state, so they don't get row-count camouflage
the same way, only orphan-status camouflage.

**Full reasoning:** `bugs.md` Bug 110 (`VaultEntry`, the original shape), Bug 112 (`Contact.Profile`,
declined), Bug 118 (`BackupEncryptionKey`, the motivating gap for extending it there);
`VAULT_KEY_LAYERING.md` §8 item 14 (`BackupEncryptionKey`'s three-state design in full).

---

## Reuse the same BEK across trustee-set changes rather than regenerating it

**Status:** Existing, shipped behavior — reasoning recorded 2026-09-12, prompted by a design
conversation questioning why `BackupEncryptionKey.Payload.bekBytes` needs to be retained at all,
given `prepareShards`/`distributeShards` already re-split and redistribute shares on every
trustee-set change anyway.

**Context:** Adding, removing, or replacing a trustee re-splits the BEK from scratch and
redistributes to every current trustee — `commitDistribution`'s own logic gives even *unchanged*
trustees a `.replace` op whenever the set changes, because `prepareShards` always calls
`ShamirSecretSharing.split` fresh for the full current recipient list, never an incremental
extension of the existing one. Since a fresh split happens anyway, the question was: why not also
generate a fresh *secret* each time, instead of reusing `bekBytes` unchanged?

**Decision:** `bekBytes` is generated once (`Backup.setup`) and reused as-is across every
subsequent trustee addition, replacement, and re-export. Only `rotate()` — a separate, deliberate
call — generates a new one.

**Why:** Reusing the same secret decouples *who can help recover* (the trustee set, changed freely
and often) from *which files can be recovered* (fixed to whatever secret sealed them). If every
trustee-set change minted a fresh secret, that same redistribution would silently orphan every
`.occbak` already sealed under the old one — any copy sitting in iCloud Drive, email, wherever —
since the newly-distributed shares only ever reconstruct the new secret. The device would then
either need to force an immediate re-export as a hidden side effect of routine trustee management,
or risk the user's most recent *usable* backup silently regressing to whatever predates the last
trustee change, with no warning either way.

**Consequences:** Every `.occbak` ever exported stays restorable by whatever the current trustee
set can reconstruct, indefinitely — trustee management and backup export stay independent user
actions, which is what they should be. The cost is symmetric and deliberate: a genuine rotation
(a suspected leaked share, a hard security reset) is the *only* path that invalidates old backups,
and it's explicit — `rotate()` is its own call, never a side effect of anything routine.

**Full reasoning:** this conversation, 2026-09-12 — not yet folded into `VAULT_KEY_LAYERING.md`'s
own prose.

**Addendum, 2026-09-14 — this decision is about `bekBytes` specifically, and does not extend to
`distributionID`.** Found while tracing `bugs.md` Bug 124 (a removed trustee's shard stays valid
forever, since neither `distributionID` nor `entryID` changes on a trustee-set mutation): the two
fields are allowed to diverge, and Bug 124's proposed fix — regenerate `distributionID` on every
trustee addition, removal, or replacement, while leaving `bekBytes` untouched — is fully consistent
with the reasoning above, not a reversal of it. The `.occbak` continuity this decision protects
depends only on `bekBytes`; confirmed directly, `VaultManager.backupFileAAD` is a fixed constant,
never `distributionID`-dependent, so nothing about an exported backup's decryptability changes when
`distributionID` does.

---

## Don't auto-arm shard collection on first vault-tab visit

**Status:** Decided, 2026-09-21 — considered and dropped in the same conversation, before any code
was written.

**Context:** Exploring ways to reduce friction in the still-unbuilt "start shard return" UX (Stage 3,
`RECOVERY_BUFFER_LAYERING.md` §9.3) — specifically, whether auto-triggering it the first time a user
ever opens the Vault tab, instead of requiring an explicit action, would work. The reasoning offered:
a genuinely fresh install has no prior distribution for any trustee to hand back, so it would be a
harmless no-op there, and would only do something useful on a real recovery (a new device, re-pairing
with trustees who still hold old shares).

**Decision:** Not building this. Checked what "start" would actually gate first: shard absorption
(`absorbShard`, shipped Stage 4, 2026-09-21) already runs unconditionally on every inbound
`.handback`, with no arming step at all. There's nothing left for a "first visit" trigger to start.

**Why:** The trustee-side reasoning (a fresh install draws no handback traffic, since nothing was
ever distributed under that identity) was sound, but it answered a question the current
implementation doesn't ask — Stage 4 already made collection passive and depth-blind, independent of
any explicit start. Building a "first visit" trigger anyway would mean introducing a *new* persisted,
checkable flag (has this vault ever been opened before) purely to gate something that isn't gated.
That flag would itself become exactly the kind of per-depth artifact this whole design has spent
effort avoiding — a coercer opening a fresh duress layer for the first time would produce the
identical stored state a genuine first run does, which is fine only as long as nothing ever reads
that flag to branch behavior differently; better not to create it at all.

**Consequences:** Stage 3's actual remaining friction is discoverability (the user needs to know a
restore/import surface exists) and one narrow mechanical gap found while discussing this:
`storePendingRestore` (opening the `.occbak` file) doesn't immediately re-check shards already
collected before the file was ever opened — it waits for the next unlock or shard arrival. Both are
still open, unscheduled. Whatever Stage 3 eventually builds for discoverability should be an ordinary
UI prompt ("restore from backup?"), not a stored "has this run before" flag.

**Full reasoning:** this conversation, 2026-09-21 — not yet folded into
`RECOVERY_BUFFER_LAYERING.md`'s own prose (Stage 3 section still unbuilt).

**Addendum, 2026-09-23: the mechanical gap named under Consequences is resolved differently.** There is
no "re-check banked shards after the file is written" step to add, because the file is no longer
written at all. See "Open the `.occbak` as a one-shot attempt at the current depth" below. The
discoverability half stands.

---

## Open the `.occbak` as a one-shot attempt at the current depth — never hold it

**Status:** Decided and built, 2026-09-23. The hole it reopened was decided the same day, see
Consequences.

**Context:** Designing Bug 99's remedy. Today `storePendingRestore` writes the opened file into the
sandbox (`backup-import-cache.occbak`) and waits for a later unlock or shard arrival to attempt
reconstruction, and completion is pinned to depth 0. Allowing completion at any depth raised the
question of whether each depth needs its own pending file.

**Decision:** The file is never held. Opening it runs one reconstruction attempt against the in-memory
bytes, at the depth it was opened at, trying every banked shard set (one `PendingShamirSecretRestore`
row per `distributionID`) against it, with the GCM tag deciding the match. Success imports there.
Failure stores nothing, and the user opens the file again once more shares have arrived. Import must
succeed at any depth, the same way.

**Why:** A held file, once completion can happen anywhere, completes at the depth of whatever attempt
comes *next*, not where it was opened: a coercer's file opened in duress lands in depth 0 at the next
real unlock. It also blocks every other depth's restore through `alreadyProcessed`. Per-depth files fix
both only by re-creating arming state, which §9.3 removed. "Attempt first, persist only on failure"
(proposed the same day) has the same two problems. Any-depth import is required because a
depth-privileged success or failure is itself a forensic trace (Bug 99).

**Consequences:**
- Removes `pendingRestoreURL`, `pendingRestoreActive`, `pendingRestoreShardCount`,
  `refreshPendingRestoreState`, the "Recovery in progress" section, and `attemptBackupRestore`'s unlock
  and shard-arrival triggers. Bug 126 becomes moot, as do Bug 100 remedy 3 and the `.occbak` half of
  remedy 1.
- `Backup.reconstruct` and `storePendingRestore` must take the real depth; both hardcode 0 today.
- The global `vault.postRestoreActionNeeded` flag has to go. It would announce a duress-layer import at
  the owner's next depth-0 unlock. Replaced by an in-memory flag reset on vault lock.
- The vault is usually locked when a file is opened (it locks whenever the app goes to the
  background). Decided the same day: Accept asks for Face ID when the vault is locked, then attempts
  at once. Keeping the bytes in memory until the next vault unlock was rejected because it brings
  back a held state.
- UX cost: the user must reopen the file after shares arrive. This reverses `VAULT_BACKUP_GUIDE.md`'s
  "no action between collection and reconstruction" requirement and leaves discoverability to Stage 3.
- **The hole it reopens:** during a genuine recovery, a coercer at a duress depth can open the real
  `.occbak` and import the real vault into his layer, because banked shards aren't bound to a depth. It
  works once (success consumes the shards) and needs a recovery in progress. Decided the same day,
  with a residual: see "Filter restore shards by trustee visibility at completion" below.
- Legacy devices can have a held `.occbak` from before this change. Decided the same day: at the first
  unlock at any depth, delete it under both filenames, plus the old shard file, without a final
  attempt. Covers the v1.10.2-and-earlier files that v1.10.3's rename orphaned (`bugs.md` Bug 127).
  Reasoning and data-loss check: `RECOVERY_BUFFER_LAYERING.md` §8.

**Full reasoning:** `bugs.md` Bug 99, 2026-09-23 addendum; `RECOVERY_BUFFER_LAYERING.md` §9.4.

---

## Filter restore shards by trustee visibility at completion

**Status:** Decided and built, 2026-09-23. Accepted with a known residual.

**Context:** The one-shot file-open design (above) lets a restore complete at any depth, and shard
collection is depth-blind. Together they let a coercer at a duress depth open the owner's real
`.occbak` during a genuine recovery and import the real vault into his layer, using shards the real
trustees handed back.

**Decision:** A restore at depth d uses only banked shards whose sender, the `senderIdentifier` already
stored in each slot, is a contact visible at d at the moment of the attempt.

**Why:** No new stored state, no codec change, no migration. It reuses the visibility model the arrival
gate (`OccultaApp.filterShardOperations`) already applies. It keeps Bug 99 closed: the coercer's own
trustees are created in his layer (`originDepth` = d), count there, and don't count at depth 0.
Considered and not chosen:
- **Accept the window:** the attacker who meets its preconditions is the one who took the old phone and
  knows a recovery is coming.
- **Bind each shard to the depth current when it arrived:** closes the default case below too, but
  needs a `ShardsCodec` v2 and a migration.

**Consequences:**
- **Residual, accepted knowingly:** a contact with no `visibleThroughDepth` is visible at every depth.
  Real trustees the owner didn't hide from a duress layer pass the filter there, so for them the hole
  stays open. Protection holds only for trustees hidden from that layer, and nothing currently prompts
  the owner to hide them.
- A coercer who separately knows the hidden trustees handed back, and holds the real file, sees it fail
  at his depth and can infer another layer exists. He gets no vault data.
- Completion needs contact visibility, which `VaultManager` doesn't read today; the caller has to
  supply it. **Settled 2026-09-23:** as two separate parameters, `currentDepth: Int` and
  `visibleContactIdentifiers: Set<String>`. These are visible *contact* IDs, not trustee IDs, because
  the restoring device doesn't know its trustees. A shard counts when its `senderIdentifier` is in
  the set. The depth stays a parameter because it decides where the result lands (which layer's key
  row, which depth the entries are stamped with), and `VaultManager` can't read it itself. The set
  can't stand in for it, since two depths can have identical visible contacts. The caller
  (`armPendingRestore`) builds the set the way `purgeDraftsNotSafeAtCurrentDepth` does: non-deleted
  contacts, `isVisible(atDepth:usingKey:)`, mapped to `identifier`. So a shard from a trustee the
  owner has since deleted doesn't count. A set was chosen over a closure so the rule stays at the call
  site and tests can pass literal sets. Bundling the two into one value was considered and declined.
- Arrival-depth binding stays the fallback if the residual proves too wide.

**Full reasoning:** `bugs.md` Bug 99, 2026-09-23 addendum; `RECOVERY_BUFFER_LAYERING.md` §9.4.

---

## No "recovery ready" signal before the `.occbak` is opened

**Status:** Decided, 2026-09-23. Nothing built; nothing to remove.

**Context:** Proposed to reduce restore friction: after a trial reconstruction on shard handback, tell
the user a recovery is possible so they know to open their backup file, and show that signal only at
depths where the trustees who handed back shards are visible.

**Decision:** No such signal, in any form.

**Why:** Deciding reason, agreed: no trial reconstruction can tell you anything without the file.
`ShamirSecretSharing.reconstruct` always returns 32 bytes, right or wrong. The only check is the GCM tag
against the file's ciphertext (`Backup.reconstruct`). The restoring device doesn't know the threshold
either (`AttestedShard`'s doc comment: "Do not build on this as if it were `threshold`-strength").
Two further problems, recorded for anyone reconsidering the idea:
- Gating the signal on trustee visibility is a depth check under another name. Real trustees aren't
  visible at a duress depth, so the signal would differ between layers, which is the difference
  Bug 93's follow-up removed by making the banner the same at every depth.
- Even a signal shown the same at every depth changes during a session when it turns on. That is the
  "live tally" reason the shard count was removed from the banner (Bug 100).

**Consequences:** The user finds out a restore is possible only by opening the file. With the one-shot
design above, that attempt is also the completion, so no separate announcement is needed.
Discoverability stays Stage 3's problem, to be solved with an ordinary prompt rather than a
readiness indicator.

**Full reasoning:** this conversation, 2026-09-23; `RECOVERY_BUFFER_LAYERING.md` §9.4.

---

## Restore discoverability: a Restore item in the Vault tab's `+` menu

**Status:** Decided and built, 2026-09-23. The restore screen is pushed onto the Vault tab's navigation
stack rather than presented as a sheet, and the post-restore prompt is bound directly to
`VaultManager.postRestorePromptPending` (no view-side copy). Not walked through in the simulator: the
vault can't unlock there, because the simulator can't create or use a Face ID-protected Secure Enclave key.

**Context:** `RECOVERY_BUFFER_LAYERING.md` Stage 3. After §9.4, restore is only reachable through "Open in
Occulta" from Files, and its steps aren't obvious. The owner has to:
1. exchange contacts again, in person, with each person holding a piece;
2. have each of them send a message, which carries the piece back;
3. open the backup file.

A failed attempt showed nothing, so trying too early looked like nothing happened.

**Decision:**
- The Vault tab's `+` button becomes a menu: "New Entry" and "Restore from Backup…". The restore item
  opens a sheet listing the three steps, ending in a file picker limited to the backup type
  (`com.github.aibo-cora.occulta.backup`). The restore then runs through the same path as "Open in
  Occulta".
- A file picked in that sheet skips the "Restore from this backup?" alert. Files arriving through "Open in
  Occulta" keep it.
- Every failed attempt, from either path, shows one neutral message at every depth.
- The existing backup-key onboarding page gets one line pointing new-phone users to the restore item.

**Why:**
- **The Vault tab, not Settings:** someone who lost their phone looks for their vault in the Vault tab.
- **A menu item:** it's always reachable, including after entries exist, and takes no screen space.
- **The steps sheet:** it puts the non-obvious steps where the action is.
- **Skipping the alert in-app:** the alert guards against a file nobody asked for. A file picked from our
  own sheet was asked for, and the sheet has already explained what happens.
- **The failure message:** safe now because every depth checks its own state. One message covers every
  failure reason, so it never reveals which one happened. This is the "truthful acknowledgment" that
  `RECOVERY_BUFFER_LAYERING.md` §4 row 6 anticipated.

Not chosen:
- **A Settings entry:** not where a new-phone owner looks.
- **An empty-vault prompt:** vanishes as soon as the layer has an entry.
- **Silence on failure:** a too-early attempt looked like nothing happened.

**Consequences:** The menu and sheet read the same at every depth, so there's no new tell. The
empty-vault text stays as it is. The weakest step is still step 2, since nothing tells the trustee to
send a message. A trustee-side prompt would fix that, as a separate decision.

**Full reasoning:** this conversation, 2026-09-23; `RECOVERY_BUFFER_LAYERING.md` §9.4.

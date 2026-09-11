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
`processInboundManifest`'s actual code confirms it; the row is never deleted on send. (A sibling
file, `PendingShardDistribute+Model.swift`, still claims "deleted on send, fire-and-forget" — stale,
not yet corrected.) Since all three op kinds already retry safely, dropping all three closes the
same "why let a coercer's session write anything at all" concern that motivated the original ask,
with no data-loss cost.

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

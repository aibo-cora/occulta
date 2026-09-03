# At-Rest Layering — Decision Framing

**Status:** §5 question 1 settled 2026-09-02 — build. Questions 2–5 not yet settled. **Compiled:**
2026-09-02.
**Owner entries:** `forensic-trace-avoidance.md` S5 (contacts) and S8 (vault entries) — the two
accepted gaps this decision would close or knowingly re-accept.
**Downstream:** `Occulta/Features/Vault/BEK_LAYERING_REFACTOR.md` §2.1, §2.2, and open decision §4.2.

**What this is.** Secure Mode layers *classification* nearly everywhere and *storage* almost nowhere.
S5 and S8 are the same gap in two model types; the BEK refactor is about to design a third instance
of the same fixed-slot pattern for a fourth consumer. This frames them as one decision, and records
what already ships so the answer is derived rather than invented — the BEK slot cap (§4.2 there) has
no anchor precisely because it was being picked before this question was settled.

---

## 1. The shared gap

| Item | What is layered | What is not | Status |
|---|---|---|---|
| S5 — sensitive contacts | `visibleThroughDepth`; the UI filter | the rows themselves stay readable under the canonical DB key, derivable on an unlocked device | accepted, "Phase 1" |
| S8 — vault entries | `visibleThroughDepth` (exact-match), stamped at activation Step 8 | `id` and `createdAt` are plaintext columns; row count is identical at every depth | accepted, Medium |

Both have one shape: **the classification is per-depth, the storage is device-wide.** It is the same
observation `BEK_LAYERING_REFACTOR.md` §1 makes about recovery — "device-wide in an app that is
layered everywhere else" — applied one level down, to the data recovery exists to protect.

That matters for sequencing. Per-layer recovery built on a store that is not itself layered inherits
the gap it is trying to close.

## 2. What already exists — and it is most of the mechanism

`LayerStore` (`SecureMode+LayerStore.swift`, `LayerStore.md`) is already a per-depth fixed-width
container, shipped:

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

That last point is the answer to "we should not impose caps, we need graceful flexibility." A fixed
envelope is not negotiable — it is what makes an occupied slot indistinguishable from an empty one
(§3 of the BEK doc's reasoning, and B3/B6 here). What *is* negotiable is whether the user can see the
budget. This codebase already chose "yes" for contacts, and that pattern is the one to copy rather
than inventing a per-entry byte cap discovered at export.

## 3. The constraint that shapes every option: three protection domains, not two

`LayerStore.md` excludes vault per-entry keys deliberately, and the reasoning generalises to vault
content as a whole:

> Storing them would widen the attack surface since a store compromise requires only the SE Secure
> Mode key, bypassing the biometric gate that otherwise protects vault content (Bug 8).

Verified directly in `Key+Manager.swift` rather than taken from prose — the domains are not two, they
are three, and one of them cuts across the BEK/vault line in a way worth exploiting:

| Key | Derived by | Biometric gate | Seals today |
|---|---|---|---|
| Secure-Mode key | (existing) | No | Contact `LayerStore`, local DB key |
| **Vault key** | `deriveVaultKey(context: LAContext)` | **Yes** | Vault entry content (`VaultManager.currentKey()` calls this directly) — **and, per `BEK_LAYERING_REFACTOR.md` §2.1's own table, the BEK record itself** |
| Recovery buffer / shard custody key | `deriveRecoveryBufferKey()` — no `LAContext` parameter | **No** | `CustodyShard` rows, the shard buffer, restore/arming state |

**Putting vault entries into the existing (Secure-Mode-keyed) store collapses domains 1 and 2 and
strictly downgrades vault protection.** It is also why S8 is rated below S5: a duress-PIN-only coercer
cannot open the vault at all, so the row-count tell needs duress PIN *and* forced biometrics to be
reachable — see §3a below for why that bar may be lower than it looks for this app's actual threat
model.

**But the BEK record is already vault-key-sealed** — the same gate as vault entry content, not the
same gate as the shard buffer it sits beside in §2.1's own per-depth slot. The shard buffer and
restore/arming state are recovery-buffer-key-sealed deliberately, and must stay that way: shards
arrive over ordinary messaging, asynchronously, and gating their receipt behind a Face ID prompt would
be a real UX regression, not just a stricter default.

**Consequence for the plan:** "use one mechanism for vault, BEK and import" holds, but resolves into
*two* shared containers rather than one, split by key domain, not by feature:
- **Vault-key-gated:** sensitive vault entries (new, if built) + the BEK record — same gate, natural
  co-tenants of one `LayerStore`-shaped file.
- **Recovery-buffer-key-gated:** the shard buffer + restore/arming state — a second, separate
  `LayerStore`-shaped file, kept unlockable without biometrics on purpose.

The exported `.occbak` backup does not join either. Its contents are sealed under the **BEK itself**,
not the vault key — necessarily, since a backup must open on a brand-new device that reconstructed the
BEK from Shamir shares and has no biometric enrollment history for this install at all. The vault key
is device-bound; the BEK is the thing designed to survive the device being gone. One exists to protect
the device you still have, the other to survive losing it — they cannot share a key without breaking
one of those two purposes.

### 3a. Is "duress PIN + forced biometrics" actually the high bar S8 assumes?

Worth naming since it changes how urgent this is, not just how it should be built. S8's downgrade
rests on that compound attack being harder than PIN coercion alone. For this app's stated threat model
— journalists, activists, people crossing borders under threat — that ordering may be backwards:
biometric unlock is compellable under a lower legal bar than a memorized PIN in multiple jurisdictions
(biometrics are frequently not treated as testimonial the way a passcode is). A border-checkpoint
coercion scenario forcing both the app's duress PIN and Face ID is closer to the default pattern for
that population than a stacked edge case. If that reasoning holds, S8's "Medium, accepted" rating
undersells the gap for the users this app is actually built for — the UI would be actively showing
"No entries yet" to a coercer holding a working extraction tool, not merely omitting a low-probability
metadata detail.

## 4. Candidates

**Contacts (S5) — build first, per §5 question 1.** Design B is already specified and deferred:
sensitive contacts become unreadable shells in the DB, the blob is the sole readable copy, loaded into
memory on normal unlock and wiped on lock. `LayerStore.md` notes the infrastructure already supports
it — no new file, no new key, four named steps. The pilot for the lifecycle pattern vault entries need.

**Vault entries (S8) — build, via option 3.** Was three candidates; 1 and 2 are superseded by §5
question 1's decision:
1. ~~Leave as-is~~ — rejected; §3a's reasoning holds.
2. ~~Decoy row padding~~ — not chosen; S8 already called this "complexity without a strong attacker
   model," and that judgment doesn't change just because the leak is now taken more seriously.
3. **Chosen.** A vault-key-gated `LayerStore` instance, holding sensitive entries as the canonical
   copy — **and, per §3, the natural host for the BEK record too**, since both already answer to the
   same key. One file with two record types from the start, built after S5's Design B lands.

**BEK and backup contents — resolves into two containers, not one, and not the sibling file
`BEK_LAYERING_REFACTOR.md` §2.2 proposes.** That proposal predates this framing and priced the BEK as
a single unit; §3's key-domain trace splits it:
- The **BEK record** joins option 3 above — vault-key-gated, alongside vault entries.
- The **shard buffer and restore/arming state** get their own recovery-buffer-key-gated
  `LayerStore`-shaped file — deliberately not biometric-gated, so shard receipt keeps working without
  an interactive unlock.
- The **exported `.occbak`** stays outside both, BEK-sealed, for the portability reason in §3.

§2.2's own objection (bulk content must stay out of `AppLayerConfig`, since SwiftData loads the whole
row on every `requireConfig()`) still applies to whichever of the two new files ends up holding the
larger payloads — likely the recovery-buffer one, since shard buffers are the more variable-sized
piece.

`CustodyShard` is a further consumer of the recovery-buffer-gated file: `LayerStore.md` records its
duress-mode accessibility as an explicitly deferred decision, and BEK §2.3–§2.4 needs the same answer.
Same key domain as the shard buffer, so likely the same container once that's decided.

## 5. Open questions

1. **Settled 2026-09-02: yes, build.** §3a's re-rating stands — for this app's actual users, "duress
   PIN + forced biometrics" is closer to the default coercion pattern than a stacked edge case, so S8's
   accepted-Medium rating undersells it. The failure isn't a passive metadata leak; it's the UI actively
   showing "No entries yet" to a coercer holding a working extraction tool.

   **Sequencing, not just scope: build S5's Design B in the same effort, first or alongside — not
   after.** The risky, unproven part of candidate 3 isn't the file mechanism (`LayerStore` already
   ships) — it's the "unreadable shell in the DB, canonical copy in the sealed file, loaded to memory
   on unlock, wiped on lock, merged with live rows in the UI" lifecycle, which has never been built
   anywhere in this codebase. Contacts' Design B is that exact pattern, already specified in four named
   steps, needs no new container or key (`LayerStore.md` — it upgrades the existing contact blob), and
   has sat deferred. Building vault entries alone makes the vault — more frequently accessed, directly
   edited by the user, higher cost if the memory lifecycle has a bug — the first real test of a pattern
   that's never run in production. Pilot it on the cheap, already-designed case first.
2. **Settled by §3's key-domain trace, not still open as a free choice:** two containers, split by
   key — vault-key-gated (entries + BEK record) and recovery-buffer-key-gated (shard buffer + restore
   state + `CustodyShard`) — not one shared instance and not one file per consumer.
3. **What is the vault-key-gated slot's budget?** Now two payload types compete for it (vault entries,
   BEK record), not one. 32 KB holds ~30 contacts with ML-KEM material; both vault entries and a BEK
   record are far smaller, so 32 KB is still a generous starting point — but it must be picked against
   the §6.5 tripwire (`VaultEntryType.document`/`.photo` stay commented out, or this design breaks).
4. **Superseded by §3/§4** — the BEK does move into this mechanism, split across the two containers
   above rather than one sibling file. What's still open: exact record layout within each slot, and
   whether the recovery-buffer file's size is dominated by the shard buffer or by `CustodyShard` once
   that consumer is folded in.
5. **Sequencing against Bug 105**, which is live on shipped code and was the reason the BEK work was
   compressed into a patch release. If the BEK refactor now waits behind this, 105 needs a deliberate
   interim answer — accept it documented, or take the remedy the BEK doc dislikes (refusing
   distribution above depth 0, which buys a new depth-conditional tell).

## 6. What this does not change

The §6.5 tripwire becomes *more* load-bearing, not less. Today `VaultEntryType`'s commented-out
`document` and `photo` cases constrain a backup format that does not exist yet. Under any option 3
here they constrain the live store as well — which is an improvement: one constraint, enforced where
it breaks loudly, instead of an assumption two separate designs quietly depend on.

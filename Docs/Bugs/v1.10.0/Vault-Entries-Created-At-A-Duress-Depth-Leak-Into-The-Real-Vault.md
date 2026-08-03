# Vault entries created at a duress depth permanently leak into the real (depth 0) vault

**Status:** confirmed, not fixed. Three candidate fixes scoped below — A and B remain quick options; **Option C is now fully scoped in detail** (see "Option C, scoped" below), but none of the three has been chosen or implemented. This doc exists to record the finding and the options for a later decision. Found while explaining the consequences of `Decoy-Vault-Entries-Unreachable-New-Entry-Sheet-Ignores-Depth.md`'s fix.

## This is not a new bug introduced by the depth-passing fix — it's inherent to the ceiling model

`VaultEntry.visibleThroughDepth` is a one-directional ceiling: a value of N means "visible at depths 0 through N, hidden beyond N" (`Manager.Security.isEntryVisible`, `Manager+Security.swift:1211-1218`). This was already true before `Decoy-Vault-Entries-Unreachable-New-Entry-Sheet-Ignores-Depth.md`'s fix — an entry wrongly stamped ceiling 0 (the old bug) was *also* already visible at depth 0 (`0 >= 0`), it was just additionally, separately broken by disappearing at the depth it was created at. That fix corrected the disappearing-at-creation-depth symptom. It did not, and structurally could not, change the underlying fact: **any entry created away from depth 0 is visible at depth 0 too, permanently, with no way to hide it from the real view.** A single scalar ceiling cannot express "hidden at depth 0, visible only starting at depth 2" — see that doc's correction section for the full reasoning.

## The risk

If someone is coerced into creating a vault entry while at a duress depth (or creates one there for any reason), that entry does not stay confined to the duress session — it becomes a permanent part of the real vault, indistinguishable in the UI from anything the user created intentionally at depth 0.

**The only clue is a plain creation date**, already displayed today:
- `Vault+Tab.swift:538` — every row shows `"\(type) · \(entry.createdAt.formatted(...))"`.
- `Vault+EntryDetail.swift:187` — full date shown in the detail view.
- The list is sorted by `createdAt` descending (`Vault+Tab.swift:81`), so a duress-created entry surfaces near the top.

This is a passive clue, not an active warning — nothing flags the entry as duress-created (no depth information is ever shown anywhere in the entry detail view, confirmed by inspection), consistent with the app's principle of never surfacing explicit depth state. Recognizing it requires the user to notice an unfamiliar row and mentally connect its date to a coercion incident.

## Candidate fixes, none chosen

**Option A — block creation entirely away from depth 0.** Hide or disable the "+" button in `Vault+Tab.swift` when `security.isRestricted`. Simplest; nothing created, nothing to leak. Risk: the button visibly behaving differently at a duress depth is itself a signal, cutting against the app's principle of never visibly betraying duress state.

**Option B — let creation appear to succeed without persisting anything.** The sheet behaves normally end-to-end; if `currentDepth != 0`, the save silently does nothing real — no `addEntry` call, nothing written. Matches the app's existing duress philosophy more closely (duress PINs themselves behave exactly like a real unlock, with different consequences underneath, never a visible "wrong" state). Trade-off: a user legitimately testing their own duress setup (not under live coercion) gets no explanation for why nothing was saved — but per the correction above, there's no decoy value being lost today, so this is likely an acceptable, deliberate cost rather than an oversight.

**Option C — real decoy support (materially bigger, scoped in full below).**

## Option C, scoped

**Status: fully scoped, not yet implemented.** Comparable in size to the entire `Group` re-encryption fix (`Group-Reencryption-Multi-Second-Block-On-Visibility-Toggle.md`), not a follow-on tweak — though it turns out to differ from that precedent (and from `GlobalShardConfig`'s per-depth schema change, `Shard-Custody-Not-Cleaned-Up-On-Contact-Deletion.md` item 3) in two important ways: simpler in its data shape, riskier in its scale.

**Data model — simpler than `Group`/`GlobalShardConfig`, no padding scheme needed.** Unlike those two, this isn't a variable-length list of identifiers per depth — it's a single yes/no per depth for one entry. That's naturally fixed-size, so it needs no slot-count decision and no padding at all:
```swift
/// Encrypted UInt32 — bit N set means visible at depth N. Always encrypts all 32
/// bits regardless of content, so unlike Group/GlobalShardConfig's variable-length
/// member lists, no padding scheme is needed — the representation is fixed-size
/// by construction.
var visibleDepthMask: Data? = nil
```
**The default must stay exactly as protective as today** — a depth-0-created entry defaults to visible-at-0-only, hidden from every duress depth, same as now. The new capability is purely additive.

**Where the logic lives — matches `Group`, not `GlobalShardConfig`.** `GlobalShardConfig`'s per-depth methods had to live on `ShardCustodyManager` because its encryption depends on an injected key manager the model can't reach on its own. `VaultEntry.visibleThroughDepth` uses the same ambient global `Data.encrypt()`/`.decrypt()` extension `Group` and `Contact.Profile` use — not `VaultManager`'s own injected vault key. So the mask read/write logic belongs directly on `VaultEntry`, the way `Group.members(atDepth:)` does. The batch-sweep orchestration (below) fits on `VaultManager` instead, since it already owns every other entry-level mutation (`addEntry`, `deleteEntry`).

**Read side needs zero caller changes.** `Manager.Security.isEntryVisible(_:)` keeps its exact existing signature — internally, check `visibleDepthMask` if present; if nil (not yet migrated), fall back to computing from the legacy `visibleThroughDepth` ceiling *without mutating anything*. Migration is a write-time concern only — mutating during a `visibleEntries` filter pass, which SwiftUI can re-invoke on every render, would be a real smell. `Vault+Tab.swift`'s existing filter needs no changes at all.

**Write side — new capability, and a subtlety worth stating precisely:**
```swift
extension VaultManager {
    /// Sets whether `entry` is visible at `depth`. Migrates entry's legacy ceiling
    /// to the new mask first if not yet migrated, then refreshes every other vault
    /// entry's mask ciphertext in the same pass — so neither which entry was just
    /// edited, nor which entries have been migrated yet, is inferable from a diff.
    func setEntryVisible(_ entry: VaultEntry, visible: Bool, atDepth depth: Int) throws
}
```
Migration can't happen in isolation, even for just the entry being edited — if entry A gets migrated because someone edited it, while untouched entry B still has `visibleDepthMask == nil`, then *whether an entry has been migrated at all* becomes its own signal, correlating with "this entry was recently touched by decoy-authoring." Same class of leak `Group`'s own doc comments warn about for padding done in isolation. Fix: any single edit's mandatory "touch every other entry" sweep must migrate *every* not-yet-migrated entry at the same time, not just the one being edited — after the first-ever decoy edit, every vault entry ends up mask-populated together, indistinguishably.

**The real risk difference from `GlobalShardConfig`: this is `Group`-scale, not singleton-scale.** `GlobalShardConfig` is one row — re-encrypting "everything" on every edit costs one key derivation, cheap by construction. `VaultEntry` is not a singleton — one row per vault item — so "touch every entry's ciphertext on any single edit" is exactly the shape of cost that caused the original multi-second `Group` hang. Must be built with the derive-once/batch-key-reuse pattern from day one, not retrofitted after the fact.

**Concrete upside: no new crypto plumbing needed at all.** `visibleThroughDepth`/the new mask use the identical ambient key (`Manager.Key().createHybridLocalEncryptionKey()`) `Group`'s fix already targets, and the key-accepting primitives already shipped for it — `Data.encrypt(using:)`/`Data.decrypt(using:)` (`Crypto+Manager.swift`) — are directly reusable here. `setEntryVisible` derives the key once, calls `VaultManager.fetchAllEntries()`, and reuses the derived key across every row's refresh, the same way `cleanUpGroupDuressMembership` already does for groups.

**Migration timing:** lazy, write-triggered, folded into the mandatory sweep — never eager at launch. Eager-at-launch *would* hit the exact crash risk `Group` already reverted once, since there are many `VaultEntry` rows, unlike `GlobalShardConfig`'s singleton case where eager was judged acceptable.

**UI:** no new authoring screen needed, matching how `Group` decoys already work — no explicit depth picker anywhere; creating or editing a decoy entry happens implicitly by already being at that depth when using the existing create/edit UI.

## The dominant risk, and required mitigations

Of everything above, one risk sits well above the rest: a subtle bug here doesn't just break a feature — it could make a real vault entry (a seed phrase, a password) visible at a duress depth it should never appear at, in exactly the scenario a real user has the least room to recover from. The following are not optional hardening — they're required properties of the implementation, and **each one must be written down as an explicit doc comment on the relevant code when this is built**, the same way `Group`'s own doc comments spell out its camouflage invariants, so the reasoning survives the person who wrote it.

1. **Fail-closed as a hard invariant.** The current ceiling code already does this — `isEntryVisible`'s decrypt-failure path returns `false`, never `true`. This must carry through explicitly: any ambiguity (decrypt failure, unexpected state, an incomplete migration) resolves toward "hidden," never toward "visible." Worst case from a bug should be an entry reverting to depth-0-only — never becoming visible somewhere it shouldn't.
2. **Fail-loud on read failure during the sweep — never a silent guessed write.** Exact lesson from the `Group` key-threading risk: a decrypt failure must never be treated as "assume empty/default and write that back." If any entry's mask can't be read/verified during the "touch everyone" sweep, the whole operation throws and aborts — nothing saves for anyone, since nothing commits until one final `save()`.
3. **One single, sanctioned writer.** All mask mutations go through the one sweep function. `visibleDepthMask` should not be a plain settable property — `private(set)` or equivalent, so bypassing the discipline is a compile error, not a code-review convention someone could violate later.
4. **Read-verify-before-commit.** After computing every entry's new sealed mask, before the batch `save()`, re-decrypt each freshly-sealed value in memory and confirm it matches the intended plaintext. Catches "encrypted the wrong thing" before it ever reaches disk.
5. **Tests targeting these exact failure modes, not just the happy path** — a wrong-key-mid-sweep test asserting the whole operation throws (mirroring the equivalent `Group` test already written), a test confirming decrypt failure resolves to hidden, and a strong regression suite confirming entries never touched by this system behave identically to today's ceiling behavior.
6. **No audit/change log, even though normal engineering practice would suggest one for debugging this class of bug.** A log of visibility changes would itself be exactly the forensic evidence a coercer or examiner could use — directly violating "must be forensic trace clean." Explicitly not a mitigation to reach for here.
7. **Manual on-device verification as a release gate, not just unit tests** — create real entries, mark some duress-only, enter the duress PIN, confirm only the intended set shows. Matches the UI-wiring verification gap already hit elsewhere this session (SwiftUI call sites aren't provably correct from unit tests alone).
8. **A dedicated review pass asking only one question:** does every code path here fail toward hidden, and is there any spot where a decrypt failure or exception gets silently swallowed? Not folded into general code review — a deliberate, separate pass.

## Not yet decided

Whether to ship A, B, or hold for C. Nothing implemented.

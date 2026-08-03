# Vault entries created at a duress depth permanently leak into the real (depth 0) vault

**Status: fixed** — see "Implementation status" at the bottom. Found while explaining the consequences of `Decoy-Vault-Entries-Unreachable-New-Entry-Sheet-Ignores-Depth.md`'s fix. **Superseded plan:** Options A/B/C and the full bitmask-based "Option C" design below were all scoped and (C) briefly implemented before a much smaller fix was found — kept in this doc for the reasoning trail, not as the shipped design. See "The actual fix: exact-depth match, not a ceiling" below.

## This is not a new bug introduced by the depth-passing fix — it's inherent to the ceiling model

`VaultEntry.visibleThroughDepth` is a one-directional ceiling: a value of N means "visible at depths 0 through N, hidden beyond N" (`Manager.Security.isEntryVisible`, `Manager+Security.swift:1211-1218`). This was already true before `Decoy-Vault-Entries-Unreachable-New-Entry-Sheet-Ignores-Depth.md`'s fix — an entry wrongly stamped ceiling 0 (the old bug) was *also* already visible at depth 0 (`0 >= 0`), it was just additionally, separately broken by disappearing at the depth it was created at. That fix corrected the disappearing-at-creation-depth symptom. It did not, and structurally could not, change the underlying fact: **any entry created away from depth 0 is visible at depth 0 too, permanently, with no way to hide it from the real view.** A single scalar ceiling cannot express "hidden at depth 0, visible only starting at depth 2" — see that doc's correction section for the full reasoning.

## The risk

If someone is coerced into creating a vault entry while at a duress depth (or creates one there for any reason), that entry does not stay confined to the duress session — it becomes a permanent part of the real vault, indistinguishable in the UI from anything the user created intentionally at depth 0.

**The only clue is a plain creation date**, already displayed today:
- `Vault+Tab.swift:538` — every row shows `"\(type) · \(entry.createdAt.formatted(...))"`.
- `Vault+EntryDetail.swift:187` — full date shown in the detail view.
- The list is sorted by `createdAt` descending (`Vault+Tab.swift:81`), so a duress-created entry surfaces near the top.

This is a passive clue, not an active warning — nothing flags the entry as duress-created (no depth information is ever shown anywhere in the entry detail view, confirmed by inspection), consistent with the app's principle of never surfacing explicit depth state. Recognizing it requires the user to notice an unfamiliar row and mentally connect its date to a coercion incident.

## The actual fix: exact-depth match, not a ceiling

While wiring up the bitmask-based Option C below, one question exposed a much simpler fix: *why build all this instead of just treating every entry as "sensitive at its own creation depth," the way `Contact.Profile` already works?*

**The answer is that this is almost what's needed — the fix is a one-line change, not a new mutation system.** `isEntryVisible`'s check was `value >= currentDepth` (a ceiling: visible from 0 through the stamped depth). Changing it to `value == currentDepth` (exact match: visible *only* at the stamped depth) closes the leak directly, with no new field, no new mutation function, no migration, and almost none of the risk scoped below.

**Why this doesn't lose anything for normal usage.** Nearly all real usage creates entries at depth 0 (Secure Mode isn't active for most users). Under a ceiling, a depth-0 entry is visible only at depth 0 anyway (`0 >= 0` true, `0 >= 1` false) — under exact match, identical result. The two models only diverge for entries created away from depth 0, which is exactly the case that needs fixing, not a case worth preserving.

**Forensic analysis, done before implementing, not after:**
- **On-disk representation is unchanged.** Same encrypted `Int`, same field, same AAD, same key. Only the comparison in `isEntryVisible` changes — a read-only interpretation of an already-existing value.
- **No new ciphertext-diff signal.** `visibleThroughDepth` was already write-once-at-creation before this fix (there was never a post-creation edit path for it) and stays that way — there's no edit event to correlate via diffing, before or after.
- **No new exposure to an examiner with the key.** Decrypting `visibleThroughDepth` reveals the identical plaintext `Int` under both interpretations — "the depth this entry was created at." Only the app's own comparison logic differs.
- **The bug was actually broader than scoped, and this closes all of it.** A ceiling makes an entry visible at *every shallower depth*, not just the real depth 0 — an entry stamped for duress depth 3 was already leaking into depth 2 and depth 1 too, not only depth 0. Exact match closes all of that uniformly.
- **No regression on the direction that already worked.** Hiding from deeper depths than creation was already correct under a ceiling and stays correct under exact match.
- **Confirmed properly scoped.** `Contact.Profile` has its own separate visibility function (`Manager.Security.isVisible(_:atDepth:)`) that genuinely depends on ceiling/range semantics — `Int.max` marks a contact "safe" (always visible), which only works because `value >= depth` is always true for `Int.max`. This fix only touches `isEntryVisible` (the `VaultEntry`-specific function); Contact classification is untouched. Confirmed via full-codebase grep that nothing else reads `VaultEntry.visibleThroughDepth`'s value directly with its own comparison logic, and that `addEntry` never produces a non-nil "always visible" stamp today, so no reachable capability is being removed.
- **Secure Mode activation/deactivation's re-encryption of this field is unaffected** — those paths decrypt the current `Int` and re-seal it under a new key during rotation; they don't interpret it, so they're indifferent to the comparison change.

**What this means for the options below:** Option C (the bitmask/migration/sweep system) is unnecessary — its entire purpose was enabling independent multi-depth visibility per entry, which turned out not to be needed to close the leak. Options A and B are also moot now that the actual fix is smaller and lower-risk than either.

## Candidate fixes, none chosen (superseded — kept for the reasoning trail)

**Option A — block creation entirely away from depth 0.** Hide or disable the "+" button in `Vault+Tab.swift` when `security.isRestricted`. Simplest; nothing created, nothing to leak. Risk: the button visibly behaving differently at a duress depth is itself a signal, cutting against the app's principle of never visibly betraying duress state.

**Option B — let creation appear to succeed without persisting anything.** The sheet behaves normally end-to-end; if `currentDepth != 0`, the save silently does nothing real — no `addEntry` call, nothing written. Matches the app's existing duress philosophy more closely (duress PINs themselves behave exactly like a real unlock, with different consequences underneath, never a visible "wrong" state). Trade-off: a user legitimately testing their own duress setup (not under live coercion) gets no explanation for why nothing was saved — but per the correction above, there's no decoy value being lost today, so this is likely an acceptable, deliberate cost rather than an oversight.

**Option C — real decoy support (materially bigger, scoped in full below).**

## Option C, scoped (superseded — not what shipped, kept for the reasoning trail)

**Status: scoped, briefly implemented, then replaced by the much smaller fix above.** Comparable in size to the entire `Group` re-encryption fix (`Group-Reencryption-Multi-Second-Block-On-Visibility-Toggle.md`), not a follow-on tweak — though it turns out to differ from that precedent (and from `GlobalShardConfig`'s per-depth schema change, `Shard-Custody-Not-Cleaned-Up-On-Contact-Deletion.md` item 3) in two important ways: simpler in its data shape, riskier in its scale.

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

## The dominant risk, and required mitigations (moot — this risk applied to the superseded Option C design, not to the fix that shipped)

Kept for the record, since it's the reasoning that led to finding the simpler fix. Of everything above, one risk sits well above the rest: a subtle bug here doesn't just break a feature — it could make a real vault entry (a seed phrase, a password) visible at a duress depth it should never appear at, in exactly the scenario a real user has the least room to recover from. The following are not optional hardening — they're required properties of the implementation, and **each one must be written down as an explicit doc comment on the relevant code when this is built**, the same way `Group`'s own doc comments spell out its camouflage invariants, so the reasoning survives the person who wrote it.

1. **Fail-closed as a hard invariant.** The current ceiling code already does this — `isEntryVisible`'s decrypt-failure path returns `false`, never `true`. This must carry through explicitly: any ambiguity (decrypt failure, unexpected state, an incomplete migration) resolves toward "hidden," never toward "visible." Worst case from a bug should be an entry reverting to depth-0-only — never becoming visible somewhere it shouldn't.
2. **Fail-loud on read failure during the sweep — never a silent guessed write.** Exact lesson from the `Group` key-threading risk: a decrypt failure must never be treated as "assume empty/default and write that back." If any entry's mask can't be read/verified during the "touch everyone" sweep, the whole operation throws and aborts — nothing saves for anyone, since nothing commits until one final `save()`.
3. **One single, sanctioned writer.** All mask mutations go through the one sweep function. `visibleDepthMask` should not be a plain settable property — `private(set)` or equivalent, so bypassing the discipline is a compile error, not a code-review convention someone could violate later.
4. **Read-verify-before-commit.** After computing every entry's new sealed mask, before the batch `save()`, re-decrypt each freshly-sealed value in memory and confirm it matches the intended plaintext. Catches "encrypted the wrong thing" before it ever reaches disk.
5. **Tests targeting these exact failure modes, not just the happy path** — a wrong-key-mid-sweep test asserting the whole operation throws (mirroring the equivalent `Group` test already written), a test confirming decrypt failure resolves to hidden, and a strong regression suite confirming entries never touched by this system behave identically to today's ceiling behavior.
6. **No audit/change log, even though normal engineering practice would suggest one for debugging this class of bug.** A log of visibility changes would itself be exactly the forensic evidence a coercer or examiner could use — directly violating "must be forensic trace clean." Explicitly not a mitigation to reach for here.
7. **Manual on-device verification as a release gate, not just unit tests** — create real entries, mark some duress-only, enter the duress PIN, confirm only the intended set shows. Matches the UI-wiring verification gap already hit elsewhere this session (SwiftUI call sites aren't provably correct from unit tests alone).
8. **A dedicated review pass asking only one question:** does every code path here fail toward hidden, and is there any spot where a decrypt failure or exception gets silently swallowed? Not folded into general code review — a deliberate, separate pass.

## Implementation status

**Done — the exact-depth-match fix, not Option C.**

- **`Manager.Security.isEntryVisible(_:)`** (`Manager+Security.swift`) — the entire fix: `value >= self.currentDepth` changed to `value == self.currentDepth`. Doc comment updated to explain why (exact match, not a ceiling) and point at this doc for the reasoning.
- **`VaultEntry.visibleThroughDepth`'s doc comment** (`Vault+Model.swift`) updated to describe exact-depth-stamp semantics instead of ceiling semantics.
- **Everything built for Option C was removed after being briefly implemented and tested**, once the simpler fix was found: `visibleDepthMask`, `MaskReadResult`, `readRawMask`, `legacyMaskEquivalent`, `isVisible(atDepth:)`/`isVisible(atDepth:usingKey:)`, `applySealedMask` (all from `VaultEntry`), the `VaultManager.setEntryVisible` sweep (`Vault+Manager+Visibility.swift`, deleted entirely), and the three `VaultError` cases added for it (`.visibilityKeyUnavailable`, `.visibilityMaskCorrupted`, `.visibilityVerificationFailed`).
- **Tests rewritten accordingly** (`VaultEntryDepthVisibilityTests` in `VaultTests.swift`) — `SetEntryVisibleTests` (7 tests for the removed sweep) deleted; the ceiling-parity tests updated to assert exact-match behavior instead, including a direct test that an entry stamped for a duress depth does *not* leak into the real depth-0 view (the actual bug this doc is about) and does not leak into other duress depths either.
- **Verified:** full `OccultaTests` suite — 670 passed, 0 real failures (one confirmed pre-existing flaky timing test, unrelated, seen intermittently throughout this session on the unmodified codebase too).
- **What's still open:** there's still no UI that lets a user build decoy entries at a specific duress depth — nothing calls `addEntry(currentDepth:)` from anywhere except the one already-fixed "+" sheet, which always uses the *current* depth implicitly. That's arguably sufficient on its own (walk into a duress depth via PIN, create entries normally, they're now correctly exact-depth-scoped) — no additional UI wiring was identified as necessary, unlike Option C's design which assumed a `setEntryVisible` call site was still needed.

# Vault entries created away from depth 0 get the wrong visibility ceiling — `VaultNewEntrySheet` never passes the current depth

**Status:** implemented — see "Implementation status" below. Found while scoping Gap 2 of `Shard-Custody-Not-Cleaned-Up-On-Contact-Deletion.md` ("duress shard operations should look real") — originally framed as "decoy vault entries can't be created"; that framing turned out to be based on a mistaken premise, corrected below before implementation.

## Correction — this is not a decoy mechanism

The original version of this doc assumed `VaultEntry.visibleThroughDepth` worked like `Group`'s per-depth membership arrays: independent content per depth, capable of showing a fake entry only at a duress depth while hiding it from the real (depth 0) view. **That's wrong.** Writing the tests for this fix surfaced it directly.

`visibleThroughDepth` is a single scalar ceiling — the same shape as `Contact.Profile`'s sensitivity model (`isSensitive`: *"visible now, hidden at the next layer"*). `isEntryVisible(_:)`'s check is `value >= currentDepth`: an entry stamped depth N is visible at depths **0 through N**, hidden **beyond** N. It is one-directional. An entry stamped depth 2 is visible at depth 0 too — it does not, and structurally cannot, hide from the real view while showing only under duress. That would require something shaped like `Group`'s independent-per-depth-array model, not an extension of this field. That's a materially bigger, separate undertaking, not something this fix provides.

So: **there is no "decoy vault entry" feature here, fixed or otherwise.** What follows is a real, narrower bug, worth fixing on its own terms.

## The actual bug

`VaultEntry` has a depth ceiling field:

```swift
// Vault+Model.swift:186-189
/// Encrypted `Int` depth ceiling.
/// nil  = visible at all depths.
/// N    = visible only at depths 0..N (created while at depth N).
var visibleThroughDepth: Data? = nil
```

`VaultManager.addEntry` accepts and stamps a depth:

```swift
// Vault+Manager.swift:205,213
func addEntry(label: String, content: Data, type: VaultEntryType, currentDepth: Int = 0) throws -> VaultEntry {
    ...
    entry.visibleThroughDepth = try JSONEncoder().encode(currentDepth).encrypt()
```

And the read side filters correctly by that ceiling — `Vault+Tab.swift`'s `visibleEntries` (lines 196-202) via `security.isEntryVisible(_:)`.

**But `Vault+NewEntrySheet.swift` — the only UI path that creates an entry — never passed a depth:**

```swift
// Vault+NewEntrySheet.swift:169 (before this fix)
_ = try self.vault.addEntry(label: self.label, content: data, type: self.selectedType)
```

`currentDepth` silently defaulted to `0`, and the view had no `Manager.Security` in its environment to pass a real value even if it wanted to.

**Actual consequence:** an entry created while at a duress depth (say depth 2) got stamped ceiling `0` instead of `2` — meaning it would be visible **only at depth 0** and hidden at depth 1 onward, including **the very depth it was just created at.** Create something while at depth 2, and it immediately vanishes from your own view at that depth, permanently, unless you happen to drop back to depth 0. That's a real, narrow, user-facing bug regardless of decoys.

## Why this was chased down at all

This surfaced while checking whether decoy `VaultEntry` support existed as a foundation for per-entry decoy trustee assignment (Gap 2 of the shard-custody doc). It doesn't provide that — see the correction above. `Vault+ShardSetup.swift` (per-entry trustee assignment) is still worth noting as already depth-agnostic in a good way (entry-UUID-scoped, trustee candidates already filtered via `security.isDisplayable(_:)`), but that's no longer relevant to unlocking genuine decoys here, since this fix doesn't create any.

## Implementation status

**Done.**

- `Vault+NewEntrySheet.swift` gained `@Environment(Manager.Security.self) private var security`, and the `addEntry` call now passes `currentDepth: self.security.currentDepth`.
- No schema or manager change — both already supported this.
- **New test coverage added** (`VaultEntryDepthVisibilityTests` in `VaultTests.swift`) — this path had zero prior coverage anywhere in the suite:
  - `addEntry(currentDepth:)` stamps the given depth and defaults to `0` when omitted.
  - `isEntryVisible`: an entry stamped depth 0 is visible only at depth 0, hidden at any deeper depth; an entry stamped depth N is visible through depth N and hidden beyond it; a legacy row with `visibleThroughDepth == nil` stays visible everywhere.
  - An end-to-end check mirroring `Vault+Tab.swift`'s actual filtering, confirming the ceiling behavior (not decoy behavior) at several depths.
- Writing these tests is what caught the wrong "decoy" premise in the first place — the first draft of the visibility tests asserted decoy-shaped behavior and failed against the (correct) implementation, which is what prompted this correction.
- **Verified:** full `OccultaTests` suite — 619 passed, 0 failed, 0 regressions.

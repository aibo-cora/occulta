# Vault entries created at a duress depth permanently leak into the real (depth 0) vault

**Status:** confirmed, not fixed. Three candidate fixes scoped below, none chosen or implemented — this doc exists to record the finding and the options for a later decision. Found while explaining the consequences of `Decoy-Vault-Entries-Unreachable-New-Entry-Sheet-Ignores-Depth.md`'s fix.

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

This is comparable in size to the entire `Group` re-encryption fix (`Group-Reencryption-Multi-Second-Block-On-Visibility-Toggle.md`), not a follow-on tweak:

1. **Data model:** `visibleThroughDepth`'s scalar ceiling needs to become a genuine per-depth-independent representation (an encrypted set/bitmask of visible depths), the same shape as `Group`'s independent per-depth member arrays rather than an extension of the current field. **The default must stay exactly as protective as today** — a depth-0-created entry defaults to visible-at-0-only, hidden from every duress depth, same as now. The new capability is purely additive: a separate entry explicitly scoped to a duress depth that never bleeds into the real view.
2. **A mutation path that doesn't exist yet.** Checked: `visibleThroughDepth` is only ever set once, at creation (`Vault+Manager.swift:213`) — there's no way to edit an existing entry's visibility afterward. Genuine decoy authoring needs incremental editing, the way `Group.addMember(_:atDepth:)` works, not a creation-time-only stamp.
3. **Migration, and a trap already hit once.** Existing rows (scalar ceiling N) need lazy, per-row migration to the new format (ceiling N → visible-at-{0...N}) — **not eager at launch.** `Group`'s `ensureDeeperSlotsPadded()` doc comment describes exactly this mistake being made and reverted already: an eager launch-time sweep "caused real device crashes/launch freezes from the sheer number of Keychain-backed crypto round trips."
4. **The dominant cost: camouflage parity with `Group`.** If a per-entry visibility edit only touches that one entry's ciphertext, an examiner diffing the database can correlate "this entry's blob changed" with "this entry was just set up as a decoy" — the exact ciphertext-diff leak `Group`'s camouflage design exists to prevent. Matching that guarantee means every vault entry's ciphertext needs a fresh-nonce touch whenever *any* entry's visibility is edited. Built the wrong way, this is precisely the shape of bug that caused the original multi-second `Group` re-encryption hang — this needs the derive-once/batch-key-reuse pattern designed in from the start, not retrofitted after the fact.
5. **UI:** no new authoring screen needed — matches how `Group` decoys already work. No explicit depth picker anywhere (the app never surfaces depth state); creating or editing a decoy entry happens implicitly by already being at that depth when using the existing create/edit UI.

## Not yet decided

Whether to ship A, B, or hold for C. Nothing implemented.

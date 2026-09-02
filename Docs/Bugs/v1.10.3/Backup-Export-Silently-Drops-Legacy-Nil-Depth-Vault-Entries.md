# Backup export silently and permanently drops legacy `VaultEntry` rows whose depth was never stamped

**Status: fixed and verified — `3e16a8e`.** Found during a routine code review of `release/v1.10.3` (three independent finder passes — line-by-line scan, cross-file caller trace, and altitude/design review — converged on the same bug from different directions, a strong signal it was real). A `VaultEntry` with a `nil` `visibleThroughDepth` (a row pre-dating the field's existence) was silently and permanently excluded from every backup export, at every depth, with no error — while the exact same entry displayed normally in the Vault tab. The two code paths disagreed about what `nil` means, and only one of them was right.

## Symptom

`VaultManager.exportBackup(currentDepth:)` calls a private helper, `entriesVisible(atDepth:)`, to decide which entries go into the `.occbak` file. Before the fix, that helper read:

```swift
// Vault+Manager+Backup.swift — pre-fix
private func entriesVisible(atDepth depth: Int) throws -> [VaultEntry] {
    try self.fetchAllEntries().filter { entry in
        guard let sealed = entry.visibleThroughDepth,
              let plain  = sealed.decrypt(),
              let value  = DepthCodec.decode(plain)
        else { return false }  // unreadable ceiling — exclude, same as isEntryVisible
        return value == depth
    }
}
```

The comment claims this matches `isEntryVisible` — the function that gates what actually shows in the Vault tab's UI:

```swift
// Manager+Security.swift — pre-fix
func isEntryVisible(_ entry: VaultEntry) -> Bool {
    guard let data = entry.visibleThroughDepth else { return true }   // nil → visible everywhere
    guard let decrypted = data.decrypt(), let value = DepthCodec.decode(decrypted)
    else { return false }
    return value == self.currentDepth
}
```

It doesn't match. `isEntryVisible`'s first `guard` short-circuits to `true` on `nil` — visible at every depth. `entriesVisible`'s combined `guard` falls through the *same* branch to `return false` — excluded. The comment is only accurate for the second case (non-nil but undecryptable ciphertext); it conflates that with the nil case, which the original code — and `Manager.Security` — treat oppositely.

## Root cause

`nil` `visibleThroughDepth` is not an edge case invented for this bug — it's a documented, deliberate state. `Vault+Model.swift`'s own field comment: *"nil = never classified, visible at all depths."* It arises exactly once in production: a `VaultEntry` row that pre-dates this field's existence, backfilled with SwiftData's lightweight-migration default (`nil`) when the column was added. Both `VaultEntry` construction sites (`addEntry`, backup import) stamp a real depth unconditionally at creation and would throw before ever persisting a nil-stamped row — so nil is confined to genuinely legacy rows, never something new code creates.

**Investigated further: is nil actually safe to treat as "visible everywhere," or is that itself the bug?** Traced through `Docs/Features/Secure Mode/bugs.md`'s Bug 26 ("Pre-existing vault entries visible in duress mode after activation") — the team already considered exactly this question. Bug 26's resolution didn't change what nil means; it made sure no `VaultEntry` stays nil once a duress depth exists. `activateSecureMode`'s Step 8 (`Manager+Security.swift`) unconditionally re-stamps every entry, nil ones included, to a hidden sentinel before that depth becomes reachable — and `deactivateSecureMode`'s Step 6 (fixed in a separate, earlier commit, `fbbe8b1`, "Fix cascade-deactivation depth exposure") deliberately does *not* flatten entries back to nil on deactivation, preserving each entry's real classification instead. Net effect: nil is structurally confined to installs with legacy entries that have never activated Secure Mode — the one population where "visible at all depths" is unambiguously correct, since there's no duress view for it to leak into.

Two independent implementations of the same three-way decode (nil / undecryptable / decoded-value) is what let them diverge silently. Neither carried a test asserting they agreed.

## Fix

Consolidated into one implementation, `VaultEntry.isVisible(atDepth:whenUnclassified:)` ([Vault+Model.swift:267](../../../Occulta/Features/Vault/Vault+Model.swift)) — the decrypt/decode/compare logic (the part `Bug 27` was about, and the part that must not fork) lives in exactly one place now. The nil case is the one thing that legitimately differs per caller, so it's an explicit parameter rather than a shared guess:

```swift
func isVisible(atDepth depth: Int, whenUnclassified: Bool) -> Bool {
    guard let data = self.visibleThroughDepth else { return whenUnclassified }
    guard let plain = data.decrypt(), let value = DepthCodec.decode(plain)
    else { return false }
    return value == depth
}
```

- `Manager.Security.isEntryVisible` ([Manager+Security.swift:1643](../../../Occulta/Features/SecureMode/Manager+Security.swift)) passes `whenUnclassified: false`. Its one call site (`Vault+Tab.visibleEntries`) only runs this check while `isRestricted` — and per the Bug 26 trace above, nil can't reach that state in practice, since Step 8 always eliminates it first. `false` costs nothing today and is defense-in-depth against a future alternate path to a duress depth that might bypass Step 8.
- `VaultManager.entriesVisible(atDepth:)` ([Vault+Manager+Backup.swift:253](../../../Occulta/Features/Vault/Vault+Manager+Backup.swift)) passes `whenUnclassified: true`. It has no `isRestricted` gate — it runs at the user's own real depth unconditionally, which is exactly where nil is reachable. `false` here would be this bug again, just deliberately this time.

A parameterized `SymmetricKey` overload (`usingKey:`) was added alongside this for an unrelated reason — see the sibling doc, `Vault-Backup-And-Shard-Recovery-Uncached-Key-Derivation.md`.

**Backstop for the invariant the fix depends on:** `activateSecureMode`'s Step 8 now carries an `assert` ([Manager+Security.swift:688](../../../Occulta/Features/SecureMode/Manager+Security.swift)) that no `VaultEntry` remains nil after the stamping loop, plus a regression test, `activation_nilDepthVaultEntry_getsStampedHidden` (`SecureModeActivationTests.swift`), inserting a nil-stamped entry and confirming Step 8 stamps it hidden. Neither existed before this fix — the Bug 26 regression itself had no direct test coverage.

## Considered and rejected: making the nil case fail closed everywhere

The instinct — "shouldn't an unclassified entry default to *hidden*, matching the undecryptable branch right next to it?" — was raised and traced through concretely rather than dismissed. It doesn't hold up: `entriesVisible`'s nil case is reached at the user's own real depth (no `isRestricted` gate protects it), so failing closed there means legacy entries silently and permanently vanish from every backup for an ordinary user who has simply never touched Secure Mode — reproducing this exact bug, deliberately, in the one place it's actually reachable. The display path's nil case, by contrast, is provably unreachable today (Step 8 already eliminates it before any duress depth exists), so fail-closed there is free defense-in-depth with no offsetting cost. The two callers needed different answers for a real, verified reason — not a shared "safer" default.

# Shard custody data is never cleaned up — on contact deletion, or on Secure Mode activation

**Status:** Gap 1 (contact deletion) implemented — see "Implementation status" at the bottom. Gap 2 (Secure Mode activation) remains unfixed and out of scope, as originally scoped. Found while investigating a separate, smaller gap (`Message.Draft` not purged on contact deletion — see `Docs/Features/Message Persistence/FINDINGS.md`, "Investigated: does `reKeyOrPurgeAll`'s `isKnownContact` check let an already-hidden contact's orphaned draft survive?").

## What `ShardCustodyManager` is

A Shamir's Secret Sharing social-recovery system for the Vault (`Occulta/Features/Vault/ShardCustody+Manager.swift:26`). A vault entry's per-entry key (PEK) is split via `ShamirSecretSharing.split` (`Occulta/Features/Vault/Vault+Manager+Shards.swift:39-133`, `prepareShards`) into `n` signed shards handed to chosen trustee contacts, recoverable once `k` of them hand shards back.

## Contact-keyed data, with no cleanup path

Several SwiftData models key data to a `Contact.Profile.identifier`, each sealed under `deriveShardCustodyKey()`/`deriveRecoveryBufferKey()` — a Secure-Enclave-derived key, independent of both the local-DB canonical key and the vault key:

- **`CustodyShard`** (`CustodyShard+Model.swift:34-83`) — trustee-side: a shard this device holds *on behalf of* an owner contact. `Payload.ownerContactIdentifier: String?`.
- **`PendingShardDistribute`** (`PendingShardDistribute+Model.swift:38-79`) — owner-side queue of shards owed to a contact. `Payload.contactIdentifier: String`.
- **`PotentiallyLostShard`** (`PotentiallyLostShard+Model.swift:31-55`) — owner-side watch list. `Payload.contactIdentifier: String`.
- **`GlobalShardConfig`** (singleton) — `Payload.trusteeIDs: [String]` (`GlobalShardConfig+Model.swift:66`), the user's default trustee set.
- **`VaultEntry.shardDistributionEncrypted`** (`Vault+Model.swift:94`) — a `ShardDistributionMetadata` containing `[ShardRecord]`, each with `contactIdentifier: String` (`Vault+Model.swift:79`).

No function analogous to `Group.purgeMember(_:)` exists anywhere in the repo for any of these (searched `purge`, `purgeCustody`, `purgeTrustee`, `purgeShard`, `removeTrustee`, `deleteShardsFor` — no matches outside tests).

The only contact-driven cleanup in this area at all is `VaultManager.markShardsLost(forContact:)` (`Vault+Manager+Shards.swift:164-199`) — and it only flips `ShardRecord.status` to `.lost` on `VaultEntry.shardDistributionEncrypted`. It does **not** touch `CustodyShard`, `PendingShardDistribute`, `PotentiallyLostShard`, or `GlobalShardConfig`. It's wired to `ContactManager.contactKeyRotated`, not to deletion:

```swift
// OccultaApp.swift:276-277
.onReceive(self.contactManager.contactKeyRotated) { identifier in
    self.vaultManager.markShardsLost(forContact: identifier)
}
```

`contactKeyRotated` fires from `update(key:for:)` (`Contact+Manager.swift:519`) on key rotation — never from contact deletion.

## Gap 1: `deleteContact` calls none of this

`ContactManager.deleteContact(identifier:)` (`Contact+Manager.swift:435-449`):

```swift
func deleteContact(identifier: String) throws {
    guard let contact = try self.fetchContact(by: identifier) else {
        throw ContactManager.Errors.contactNotFound
    }

    let softDeleted = try self.fetchSoftDeletedContacts()
    if softDeleted.count >= 50, let victim = softDeleted.first {
        self.modelContext.delete(victim)
    }

    contact.deletionToken = try Data([1]).encrypt()
    try self.modelContext.save()

    try self.forEachGroup { try $0.purgeMember(identifier) }
}
```

Sets `deletionToken`, purges group membership — calls no shard-custody function, no `markShardsLost`, nothing.

**Concretely, what survives deleting a contact today:**
- If they were a **trustee**: their `ShardRecord` on your vault entry keeps its active (`.pending`/`.confirmed`) status forever — never marked lost, never revoked. Depending on how recovery-threshold counting works elsewhere, a deleted, unreachable trustee could still count toward "enough shards available" even though they can never actually hand one back.
- If they were an **owner** whose shard this device holds in custody: the `CustodyShard` row survives untouched — **this device keeps holding real cryptographic shard material for a contact the user just deleted, indefinitely.**
- Any queued `PendingShardDistribute` row for them keeps trying to attach `.distribute` operations to outbound bundles for a contact that no longer exists.
- Any `PotentiallyLostShard` watch row for them survives.
- `GlobalShardConfig.trusteeIDs` keeps their identifier if they were a default trustee.

## Gap 2: none of this is touched by Secure Mode activation either

Checked `Manager+Security.swift`'s `activateSecureMode` end to end for any reference to `CustodyShard`, `ShardCustody`, `PendingShardDistribute`, `PotentiallyLostShard`, `GlobalShardConfig`, or shard reconstruction — zero matches. Step 4 (line 404) classifies and blobs contacts; Step 8 re-encrypts `VaultEntry.visibleThroughDepth` and calls `Message.Draft.reKeyOrPurgeAll` (lines 486-512). Shard-custody tables are sealed under a key entirely separate from the local-DB canonical key that activation rotates (`Key+Manager.swift:816`, `855`).

So shard custody isn't just missing from contact deletion — **it sits completely outside the Tier 1/Tier 2 duress-protection framework everything else in this app is built around.** A contact becoming sensitive, or a genuine duress-PIN entry, does nothing at all to shard custody data tied to that contact — no reclassification, no rekey, no purge.

## Why this is more significant than the drafts gap it was found alongside

The drafts gap (a deleted contact's orphaned `Message.Draft` surviving re-keying) is conversation content. This is live cryptographic recovery material — a device continuing to hold actual shard bytes for a contact the user has already deleted, with no expiry, no purge, and no interaction with the app's own duress-protection model at all.

## Gap 1 (contact deletion) — implemented

**Status: implemented** (`1b1d387`, `ShardCustodyManager.purgeCustody(for:)` plus a call to `vaultManager.markShardsLost(forContact:)`, both wired into `deleteContact`), **with test coverage** (`OccultaTests/Vault/ShardCustodyPurgeTests.swift`). The deferred `GlobalShardConfig` depth-gating question below was resolved as part of landing this — see "Resolved — unconditional, not depth-gated."

What follows records the scoping this was built from, for reference.

**`ContactManager` doesn't hold `VaultManager` or `ShardCustodyManager` today.** The only existing cross-manager reference is `security: Manager.Security` (`Contact+Manager.swift:57,64`). This codebase already has a precedent for exactly this situation, though: `encryptGroupBundle` and `activateSecureMode` both take `vaultManager: VaultManager? = nil`/`vaultManager: VaultManager` as a parameter rather than a stored reference. `deleteContact` should follow the same shape — add `vaultManager: VaultManager? = nil, shardCustodyManager: ShardCustodyManager? = nil` as parameters, optional and nil-safe so a call site without them just skips this cleanup rather than failing. The two UI call sites (`Contact+Form.swift:177`, `ContactFormV2.swift:200`) would need to pass these through from their own `@Environment` — both managers are already injected at the app root (`OccultaApp.swift`), so this is adding an environment read at the call site, not new wiring through the tree; worth confirming those two specific files declare it already or need to add it.

**`ShardCustodyManager` and `ContactManager` share one `ModelContainer` but use separate `ModelContext` instances** (`OccultaApp.swift:82,89` — same container passed to both, but each wraps it in its own context). So `ContactManager.modelContext.save()` does *not* cover mutations to `CustodyShard`/`PendingShardDistribute`/`PotentiallyLostShard`/`GlobalShardConfig` — any cleanup touching those needs its own save through `ShardCustodyManager`'s context, not folded into `deleteContact`'s existing save.

**The natural shape: one new method, `ShardCustodyManager.purgeCustody(for identifier: String)`**, called from `deleteContact` (`shardCustodyManager?.purgeCustody(for: identifier)`), doing all four pieces in one pass through its own context and saving once at the end:

1. **`CustodyShard`** — delete every row where `ownerContactIdentifier == identifier`. Two existing precedents delete `CustodyShard` by owner identifier already (`deleteMismatchShards(for:newFingerprint:)`, `processExpectedShards(_:from:senderPublicKey:)`, both in `ShardCustody+Manager.swift`) — neither fits as-is, since both additionally gate on fingerprint matching for their own (different) purposes. A contact-deletion purge needs a plain variant with no fingerprint condition, reusing the same `modelContext.delete(row)` + save pattern, not the gating logic.
2. **`PendingShardDistribute`** — delete every row where `contactIdentifier == identifier`. No existing by-contact deletion; the only delete function (`deletePendingDistribute(attributeID:using:rows:)`) is keyed by `attributeID`. New code, but structurally simple: fetch, filter, delete.
3. **`PotentiallyLostShard`** — delete every row where `contactIdentifier == identifier`. No delete function exists for this type at all today (only insert and an in-place `isAbsent` mutation) — new code, same simple shape.
4. **`GlobalShardConfig.trusteeIDs`** — remove `identifier` from the array. No targeted removal exists; the only write path (`saveGlobalShardConfig(_:)`) deletes the whole singleton and reinserts a fresh one from a caller-supplied payload. This step means: decrypt the current payload, filter `identifier` out of `trusteeIDs`, call `saveGlobalShardConfig` with the filtered result — reusing the existing write path rather than adding a second one.

**Separately, `deleteContact` also calls `vaultManager?.markShardsLost(forContact: identifier)`** — this function already exists, already handles `VaultEntry.shardDistributionEncrypted`'s `ShardRecord` correctly, iterates every entry itself, and saves itself. No new code needed here, just the missing call site.

**Two things to flag before implementing, not silently assumed:**

1. **Deleting a `CustodyShard` for a since-deleted owner is permanent and one-way.** Almost certainly correct — there's no legitimate reason to keep holding recovery material for someone no longer a contact — but if that contact is later re-added, whatever secret they were relying on this device to help recover is now down one shard, permanently, with no automatic path back. A real product/security tradeoff worth explicit sign-off, not an assumption to bake in silently.
2. **`markShardsLost` silently no-ops if the vault happens to be locked at the moment of deletion** (`guard let vaultKey = try? self.currentKey() else { return }`) — this is a pre-existing characteristic of the function, not something this fix introduces or closes. Its own doc comment says cleanup defers to the next `.inquire` cycle. Reusing it inherits this gap rather than closing it; worth stating plainly rather than implying the fix is airtight-synchronous.

**Resolved — unconditional, not depth-gated.** Investigated before deciding: `GlobalShardConfig`/`trusteeIDs` has no depth-awareness anywhere in the codebase today — `saveGlobalShardConfig`/`globalShardConfig()` never reference `currentDepth`, and the sole trustee-selection UI (`VaultGlobalTrustees.swift`) has no per-depth variant or duress branching. More importantly, the codebase's own existing precedent settles this: `Group.purgeMember(_:)` (used by `deleteContact` for group membership) is explicitly *not* depth-gated, precisely because removing one identifier that's "invalid everywhere" and touching nothing else can't destroy anyone else's decoy content — unlike `cleanUpGroupDuressMembership`'s broader hygiene sweep, which *is* gated because it reaches across depths. `trusteeIDs` removal-on-deletion matches `purgeMember`'s shape (single identifier, single list, nothing else touched), not the hygiene-sweep's shape — so it follows the same unconditional pattern.

**Gap 2 (Secure Mode / duress integration) stays entirely out of scope for this pass**, unchanged from the original finding — a bigger, separate design question about what protection tier shard custody data should have under duress, not something to fold into a contact-deletion fix.

## Gap 2, scoped

**Status: fully scoped (five pieces, grounded against current code), not yet implemented.** See "Build order this implies" near the bottom before starting.

**No screen in this app hides itself entirely at a non-zero depth** — confirmed by searching every `currentDepth`/`security.` read in `Occulta/UI/`. The architecture is consistently per-row/per-entry filtering (a hidden contact just doesn't appear in a list; `VaultManager` itself has zero depth-awareness, only the Vault tab's row-level `isEntryVisible` filter does). Any Gap 2 fix should follow that same shape, not invent a coarser "disable this screen" mechanism.

**Adding a biometric gate to the shard-custody key (mirroring Vault's own PEK protection) is not viable.** `deriveShardCustodyKey()`'s own doc comment: "No LAContext needed... enables fully automatic shard operations on bundle receipt." Incoming `.distribute`/`.replace`/`.handback` ops must be processed transparently in the background; adding Face ID here would break automatic reconciliation entirely.

**A concrete, live leak, not a hypothetical:** `Vault+Tab.swift`'s "Custodian Shards" section (lines 405-445, 459-476) renders the real decrypted name of every contact whose shard this device holds, unconditionally — `self.allContacts` is queried via `Contact.Profile.descriptor`, which filters only `deletionToken == nil`, no depth check anywhere. Same gap in `VaultGlobalTrustees.swift`'s trustee picker.

**Existing precedent to reuse, already correct in one place:** `Manager.Security.isDisplayable(_:)` (`Manager+Security.swift:1197`) is the exact filter needed, and `Vault+ShardSetup.swift` (the per-entry trustee-assignment screen) already uses it correctly (`allContacts.filter { self.security.isDisplayable($0) }`, line 53) — its `globalTrusteeIDs` badge lookup reads the unfiltered `GlobalShardConfig` directly but is safe by consequence, since a hidden contact never gets a candidate row to attach a badge to.

**Full pass confirms the fix surface is exactly two files:** `Vault+Tab.swift`'s custodian section and `VaultGlobalTrustees.swift`'s picker. `PendingShardDistribute`/`PotentiallyLostShard` have no UI display surface anywhere — every other UI reference to shard-custody types (`ComposableMessage`, `ComposeViewModel`, `ContactDetailV2/V3`, `GroupDetailV3`, `Contact+Form`, `ContactFormV2`) is plumbing for outbound bundle composition, not display.

**Decisions made:**

1. **A hidden custodian/trustee's row disappears entirely** — no redacted placeholder. Extends the same accepted tradeoff already applied to hidden contacts/groups everywhere else; not a new kind of leak. Filter key: is the owner contact currently visible at this depth, via `isDisplayable`/`isVisible(_:atDepth:)`; an unresolvable owner identifier should also not render outside depth 0.
   - `Vault+Tab.swift`'s custodian section is pure display, no save action — zero risk of the destructive-overwrite class of bug this decision could otherwise create.
   - **`VaultGlobalTrustees.swift` is different: it has a save action, and this is where the risk actually lives.** Filtering the *displayed* candidate/selected list and then saving must merge the edited, currently-visible subset back into the full underlying `trusteeIDs` array — never replace it wholesale, or a duress-depth edit would silently delete every currently-hidden trustee from the real config. `Group.purgeMembersFromDuressDepths`'s own doc comment describes fixing precisely this class of bug once already ("this replaces an earlier version... that had exactly that destructive side effect").
   - Open, small UI decision: whether `Vault+Tab.swift`'s "Custodian Shards" section should always render (showing its existing empty-state text when the filtered count is zero) rather than disappearing entirely when filtered count is zero — leaning toward always-render, matching how empty lists already behave elsewhere in the app, so the section's mere presence/absence isn't itself a tell.

2. **No decoy-authoring mechanism needed for these two surfaces** — superseded below. Decoys matter for Contacts/Groups because most real users are expected to have non-trivial real content there — an empty contacts list looks wrong under scrutiny. Vault trustees/custodianship is a niche feature; not using it at all is common and unremarkable for most users, so a reduced or empty state doesn't carry the same implicit suspicion by itself.

**Revisited: decoy shard operations are wanted after all** ("duress mode shard operations should look real"), so decision 2 above is superseded for the two confirmed surfaces. This needs:
- `GlobalShardConfig` to gain real per-depth storage (a slot per depth, the same shape as `Group`'s `realMemberSlots`/`duressMemberSlots`/`deeperMemberSlots` — reusing that proven scheme is the leading option over inventing a simpler shared-duress-tier, which would reintroduce the exact granularity problem Bug 73 already fixed for `Group`). `VaultGlobalTrustees.swift` then needs `Manager.Security`/`currentDepth` added (it has neither today) to read/write the active depth's own slot — no new authoring UI needed, matching how `Group+FormV3` already works simply by being depth-parametric.
- A **new, separate, purely cosmetic store** for `Vault+Tab.swift`'s "Custodian Shards" section — real `CustodyShard` rows carry actual signed shard bytes from a real protocol exchange, so a decoy entry can't reuse that model without risking the automatic reconciliation logic (`handleInbound`, manifest processing) treating fake data as real. This needs its own small per-depth sealed store (owner display name + a shard count to show), with no real cryptographic material and no interaction with the actual shard protocol.

**Correction, found while implementing the prerequisite below:** this does *not* extend to per-entry trustee assignment after all. [`Decoy-Vault-Entries-Unreachable-New-Entry-Sheet-Ignores-Depth.md`](Decoy-Vault-Entries-Unreachable-New-Entry-Sheet-Ignores-Depth.md) turned out to be based on a mistaken premise — `VaultEntry.visibleThroughDepth` is a one-directional ceiling (visible from depth 0 through N, hidden beyond N), the same shape as `Contact.Profile`'s sensitivity model, *not* `Group`'s independent-per-depth-array decoy model. An entry stamped depth 2 is still visible at depth 0 — it can't hide from the real view while showing only under duress. That doc's fix is real and now implemented (it corrects an actual bug: an entry created while at a duress depth was wrongly stamped ceiling 0, hiding it even at the depth it was just created at), but it does not unlock decoy vault entries, and `Vault+ShardSetup.swift`'s depth-agnostic trustee assignment is no longer relevant here as a result — there's still no way to create a vault entry that's hidden at depth 0 and shown only under duress. Extending decoys to per-entry trustee assignment would need a `Group`-style independent-per-depth storage change to `VaultEntry` itself — a materially bigger, separate undertaking, not scoped here.

**Prerequisite `Vault+NewEntrySheet` fix: done** (`183e8f8`, tracked in the sibling doc). Everything below is grounded against a fresh read of the actual current code, not the decisions above alone — this has five distinct pieces, more than the drafts fix had, and none of the current code does any of it yet.

### 1. `Vault+Tab.swift` — filter the real custodian list

`custodianRows` (lines 453-476) currently resolves each `heldShards`-grouped `ownerContactIdentifier` against `self.allContacts` (`Contact.Profile.descriptor` — `deletionToken == nil` only, no depth check) with no filter at all. Fix: resolve the owner, then keep the row only if `security.isDisplayable(contact)`; drop it if the owner can't be resolved to a contact at all, unless at depth 0 (matching decision 1's "an unresolvable owner identifier should also not render outside depth 0"). `VaultTab` already injects `@Environment(Manager.Security.self) private var security` for the personal-entries list (lines 199-202) — reuse the same instance, no new plumbing needed here.

The section's two emptiness checks (`!self.rawCustodyShards.isEmpty` at line 405, and the inner empty-state branch at line 407) both key off the *unfiltered* real query. Once decoys exist (item 4), these need to check the *merged* real+decoy list instead, or a duress depth with real custodians hidden but decoys present would incorrectly show the empty state.

### 2. `VaultGlobalTrustees.swift` — filter the picker, and fix the save path for real

Confirmed by direct read: `mlkemContacts` (lines 25-27) has no depth filter, and neither does anything else in the file — no `Manager.Security` is injected anywhere today. `loadConfig()` (lines 266-269) seeds `selectedIDs` from the *entire* stored `trusteeIDs`, and `save()` (lines 271-278) calls `saveGlobalShardConfig(.init(trusteeIDs: Array(selectedIDs)))` — a **wholesale overwrite**, confirmed by reading `saveGlobalShardConfig` itself (`ShardCustody+Manager.swift:426-436`, which deletes every row and inserts exactly one fresh one from whatever payload it's given, with no awareness of anything prior).

Today, with no filtering at all, this overwrite is harmless — whatever's selected *is* everyone. The moment `mlkemContacts`/`selectedIDs` get filtered through `isDisplayable` (this fix), that stops being true: `selectedIDs` would only ever contain currently-visible identifiers, and `save()`'s literal `Array(selectedIDs)` would silently drop every hidden trustee. Fix, in order:
1. Add `@Environment(Manager.Security.self) private var security` to this view.
2. Filter `mlkemContacts` (candidates) and the seeded `selectedIDs` (from `loadConfig()`) through `security.isDisplayable(_:)`.
3. On save, fetch the *current, full* `trusteeIDs` first, split it into `hiddenIdentifiers` (not currently displayable — untouched, since the UI never showed them and `selectedIDs` says nothing about them either way) and everything else, then write `hiddenIdentifiers + Array(selectedIDs)` — merge, never `Array(selectedIDs)` alone.

### 3. `GlobalShardConfig` — per-depth schema change

Confirmed current shape is a single flat `struct Payload: Codable { let trusteeIDs: [String] }` (`GlobalShardConfig+Model.swift:65-67`) — no depth concept, no fixed slot count, no padding. This needs more than "one array per depth": `Group`'s scheme (`realMemberSlots`/`duressMemberSlots`/`deeperMemberSlots`, fixed `slotCount = 32`, fixed-size padded `Data` entries, `slotSize = 156`) exists specifically so real and filler slots produce *identical ciphertext sizes* — a flat, depth-indexed `[String]` array whose length varies between a real depth (2 real trustees) and a decoy depth (1 decoy trustee) would recreate exactly the size-differential tell padding was built to avoid elsewhere in this codebase. The fix should mirror `Group`'s *full* discipline, not just its top-level array shape: fixed-size padded slots, and — critically — `Group.setMembers`'s "re-encrypt every depth on any single-depth edit" rule (confirmed private, only reachable via `addMember`/`removeMember`, `Group+Model.swift:297-311`), which exists specifically to stop depth-to-depth ciphertext diffs revealing which single depth was just edited (Bug 73). A `GlobalShardConfig` fix that only rewrites the depth actually being edited reopens that exact class of leak.
Read/write shape needed: an `addTrustee(_:atDepth:)`/`removeTrustee(_:atDepth:)` public pair backed by a private `setTrustees(_:atDepth:)`, matching `Group`'s public/private split exactly.
Migration: existing installs have a flat `trusteeIDs` with no depth concept at all — needs to land as depth-0-only content on upgrade, matching how `Group` already handles pre-1.9.1 rows ("absent until first post-upgrade edit, at which point `setMembers` pads it to full size").

### 4. New decoy-custodian display store — and a hard constraint on what it can contain

Confirmed `CustodyShard.Payload` (`CustodyShard+Model.swift:73-82`) carries a real `SignedAttribute` — an actual owner-signed Shamir shard from a genuine protocol exchange, consumed by `handleInbound`/manifest reconciliation. A decoy entry cannot reuse this model without either crashing that reconciliation code or, worse, having fake data mistaken for recoverable material. The new store needs nothing but an encrypted display name and a shard-count integer, sealed under `deriveShardCustodyKey()` like everything else in this system, with zero interaction with the real shard protocol — no `SignedAttribute`, no fingerprint, never touched by `handleInbound`.

**A constraint worth stating explicitly, not implied:** the decoy display name must be entirely fabricated — never a real contact's name, hidden or not. Reusing an actual hidden contact's identity as decoy-custodian "flavor text" would mean that contact's real name renders in the clear (once decrypted) at a duress depth specifically designed to keep them invisible — a direct, catastrophic leak of exactly the thing being protected, worse than anything else in scope here. Generation approach can be as simple as this system needs — a small fixed set of plausible display-name shapes is enough; this doesn't need the drafts feature's OS-dictionary/anti-fingerprinting rigor, since a person's name isn't trying to pass as typed prose.

Same per-depth storage discipline as item 3 applies here too (fixed-size padded slots, whole-scheme re-encryption on any single-depth edit) — same underlying problem, same fix shape.

### 5. Wiring the decoy store into `Vault+Tab.swift`

Confirmed minimal: `custodianRows` already produces a plain `{ownerIdentifier, ownerName, count}`-shaped row (`CustodianRow`, lines 453-457) consumed by an unconditional `ForEach` (lines 413-433) with no real-vs-decoy distinction baked into the row type or the rendering code. Once item 1's filtering and item 4's store both exist, the only change needed is in assembly: concatenate the depth-filtered real rows with rows read from the new decoy store at `security.currentDepth` into one array before it reaches the `ForEach` — no new row view, no new template.

### Build order this implies
Items 1 and 2 (filtering + the merge-not-overwrite save fix) are independently useful and lower-risk — they close the live leak even with zero decoy content, and don't depend on anything else here. Items 3, 4, and 5 (the actual decoy machinery) are a materially bigger undertaking, only worth it once 1 and 2 are done and confirmed safe on their own.

## Implementation status

**Done — Gap 1 only.**

- **`ShardCustodyManager.purgeCustody(for:)`** (`ShardCustody+Manager.swift`) — derives the shard-custody key once and reuses it across all four steps: deletes `CustodyShard` rows by `ownerContactIdentifier`, `PendingShardDistribute` rows by `contactIdentifier`, `PotentiallyLostShard` rows by `contactIdentifier` (all three: fetch, filter, delete — no existing by-contact deletion for the latter two, matching the doc's original plan), and removes the identifier from `GlobalShardConfig.trusteeIDs`, saving once at the end.
- **`GlobalShardConfig` is always resaved**, even when the deleted identifier was never a trustee and even when no `GlobalShardConfig` row existed at all before this call — a fresh row is created either way. This closes two related forensic signals: (a) which deletions actually removed a trustee, and (b) whether this user has ever configured Vault trustees at all (absence of any row would otherwise itself be a signal). Verified by `resavesUnconditionally_evenWhenIdentifierWasNeverATrustee` and `createsConfigRow_evenWhenNoneExistedBefore` in `ShardCustodyPurgeTests.swift`.
- **`ContactManager.deleteContact`** (`Contact+Manager.swift`) gained `vaultManager: VaultManager? = nil, shardCustodyManager: ShardCustodyManager? = nil` — optional, nil-safe, matching the `encryptGroupBundle`/`activateSecureMode` precedent. Calls `shardCustodyManager?.purgeCustody(for: identifier)` (errors propagate, matching how the existing group-purge step already behaves — the soft-delete itself has already been committed by this point regardless) then `vaultManager?.markShardsLost(forContact: identifier)` (existing function, no changes, inherits its existing "no-ops if vault is locked, deferred to next `.inquire` cycle" characteristic, flagged as a pre-existing gap in the original finding above, not something this fix closes).
- **Both UI call sites updated** (`Contact+Form.swift`, `ContactFormV2.swift`) to read `VaultManager`/`ShardCustodyManager` from `@Environment` (already injected at the app root, `OccultaApp.swift`) and pass them through.
- **Tests added:** `ShardCustodyPurgeTests.swift` (9 tests — per-store removal, cross-contact isolation, the two camouflage cases above, and a combined-pass test) plus one integration test in `GroupModelTests.swift` (`deleteContact_withShardCustodyManager_purgesGlobalShardConfigTrustee`) confirming `deleteContact` actually invokes `purgeCustody`, not just that `purgeCustody` behaves correctly in isolation.
- **Verified:** full `OccultaTests` suite — 613 passed, 0 failed, 0 regressions.

**Deliberate side effect worth knowing about:** because `GlobalShardConfig` is now always resaved on every contact deletion, **any user who deletes even one contact, ever, will end up with a `GlobalShardConfig` row in their database — even if they've never touched the Vault or trustee features at all.** This is the intended consequence of closing signal (b) above, not an oversight, but it's a real, permanent behavior change worth being aware of rather than discovering incidentally.

**Not done:** Gap 2 (Secure Mode activation) — unchanged, still entirely out of scope.

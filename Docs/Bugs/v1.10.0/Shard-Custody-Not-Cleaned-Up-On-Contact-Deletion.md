# Shard custody data is never cleaned up — on contact deletion, or on Secure Mode activation

**Status:** Gap 1 (contact deletion) implemented. Gap 2 items 1–2 (filter the two live-leak surfaces, fix the merge-not-overwrite save bug) implemented. Gap 2 item 3 implemented and fully consolidated — re-scoped from the original `GlobalShardConfig` per-depth schema change to a simpler per-contact `globalTrusteeDepth` field, then upgraded from a two-mechanism split to `globalTrusteeDepth` as the single trustee mechanism at every depth including 0, with `GlobalShardConfig` migrated, orphaned, and scheduled for removal — see items 3 and 3a below. Items 4–5 (the decoy-custodian store, wiring it into the Vault tab) are now fully re-scoped — same exact-match-per-row pattern as item 3's final design, replacing the original padded-slot outline — and confirmed worth building (closes a structural real-vs-duress asymmetry, not just cosmetic polish), but not yet implemented. Separately confirmed and test-verified while scoping items 4–5: real shards from *safe* contacts already get correct ceiling-based visibility at duress depths today, for free, off the existing contact classification — no fix needed for that case, see "Confirmed: real shards from safe contacts..." below. A follow-on duress-signaling spec was explored while scoping items 4–5 (see "Duress signaling for shard custody" near the bottom): its low-lift pieces are implemented — `purgeCustody` now re-seals surviving rows on every purge (closing a diff-comparison tell), and normal shard operation under duress is verified end-to-end by a new test, not just assumed. Full DB-existence camouflage remains open and separately scoped, bigger than items 4–5. Its covert-signal requirement was found to hand a coercer direct proof of a help attempt and is not being pursued as specified. Found while investigating a separate, smaller gap (`Message.Draft` not purged on contact deletion — see `Docs/Features/Message Persistence/FINDINGS.md`, "Investigated: does `reKeyOrPurgeAll`'s `isKnownContact` check let an already-hidden contact's orphaned draft survive?").

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

### 3. `GlobalShardConfig` — superseded by a simpler per-contact design

**Status: implemented**, but not as originally scoped below. The padded-per-depth-slot design (`Group`-style `trusteeSlots: [[Data]]`, 16-slot cap, lazy migration, overage handling — the full original write-up is preserved in git history for this file) was re-examined against the same "are we over-engineering this" question that led to simplifying the vault-entries-leak fix (see `Vault-Entries-Created-At-A-Duress-Depth-Leak-Into-The-Real-Vault.md`) and found to be solving a bigger problem than actually exists: `GlobalShardConfig` never needed genuinely different decoy *content* per depth (`Group`'s reason for padded slots) — it only needed to stop leaking the real depth-0 list into a duress-depth context.

**What shipped instead:** `Contact.Profile.globalTrusteeDepth` — one encrypted field per contact, exact-match semantics mirroring `VaultEntry.visibleThroughDepth` (not a ceiling, not a padded array): `-1` = not a trustee, `N` = trustee at exactly depth `N`. No slot count, no padding, no per-depth migration — each contact just carries its own stamp, like every other per-entity depth field in this codebase.

**`GlobalShardConfig` is fully consolidated onto `globalTrusteeDepth` (originally shipped as Option 2, later upgraded to full consolidation — see below).** `Vault+ShardSetup.swift`'s `globalTrusteeIDs` and `VaultGlobalTrustees.swift`'s `loadConfig()`/`save()` read and write `Contact.Profile.globalTrusteeDepth` unconditionally now, at every depth including 0 — no depth branch, no `GlobalShardConfig` reference left in either file. This directly avoids the "merge-not-overwrite" problem the original per-depth-slot design would have inherited from flat storage — there's no shared array to corrupt, since each contact's designation is a fully independent field.

**Forensic tell closed the same way as `visibleThroughDepth` (S6).** A `nil`/non-nil column split on `globalTrusteeDepth` would itself be a tell (see `forensic-trace-avoidance.md` S9) — the field is always stamped at contact creation, preserved through activation/deactivation re-keying (including the blob round-trip), and backfilled for pre-existing contacts, so nil is never a valid steady state.

**Cap on trustee count:** not needed. The 16-vs-32 slot-count question in the original design only existed because of the padded-array shape; a per-contact field has no slot budget to exhaust, so this question is moot under the shipped design.

**Tests:** `OccultaTests/Contacts/GlobalTrusteeDepthTests.swift` (reads, writes, backfill migration, `GlobalShardConfig` isolation, the consolidation migration) and `GlobalTrusteeDepthPreservationTests` in `SecureModeActivationTests.swift` (activation/deactivation preservation, blob round-trip, sentinel-not-nil after deactivation).

#### 3a. Full consolidation: `GlobalShardConfig` orphaned entirely

**Status: implemented.** Initially shipped as Option 2 (`GlobalShardConfig` kept as the sole depth-0 source, `globalTrusteeDepth` handling only duress depths) — deliberately the smaller diff at the time, since the leak this item fixes only ever existed at duress depths. Immediately consolidated into a single mechanism once asked: is there a reason to keep two coexisting trustee stores when one already covers every depth? There wasn't — `globalTrusteeDepth`'s exact-match semantics work identically at depth 0.

**What changed:**
- `DatabaseMigration.migrateGlobalShardConfigToPerContact` (`PQmigration.swift`, run unconditionally in `OccultaApp.migrate()`) reads any existing `GlobalShardConfig.trusteeIDs` once, stamps `globalTrusteeDepth = encrypt(0)` on each of those contacts, and deletes the `GlobalShardConfig` row(s). Idempotent — the row-existence guard makes every run after the first a no-op.
- `Vault+ShardSetup.swift` / `VaultGlobalTrustees.swift` — the depth-0 branch removed entirely; both files now call `ContactManager.globalTrusteeIdentifiers()`/`saveGlobalTrusteeDepth(selectedIDs:)` unconditionally.
- `ShardCustodyManager.purgeCustody(for:)` — the `GlobalShardConfig.trusteeIDs` removal step (former step 4) deleted outright, not just skipped. A deleted contact's `globalTrusteeDepth` lives on their own row, which `deleteContact` already soft-deletes, and every trustee read (`isGlobalTrustee`/`globalTrusteeIdentifiers`) already excludes soft-deleted rows — nothing separate to purge. This *simplifies* Gap 1's shipped code rather than extending it.
- `ShardCustodyManager.decryptGlobalConfig(_:)`, `saveGlobalShardConfig(_:)`, and `saveGlobalShardConfig(mergingVisibleSelection:isVisible:)` deleted — no callers left. `globalShardConfig()` (read-only) kept, used only by the migration above.

**`GlobalShardConfig` the model stays declared in the schema, deliberately, for one release.** This project has no `VersionedSchema`/`SchemaMigrationPlan` — schema changes rely entirely on SwiftData's automatic lightweight-migration inference. Dropping a whole `@Model` type from the `Schema([...])` array is a bigger, less-tested kind of change than the property-level additions this project has made so far, and betting on it correctly handling real user data (some of whom already have a `GlobalShardConfig` row, per Gap 1's "deliberate side effect" note above) wasn't worth the risk for a purely cosmetic cleanup. The model is fully orphaned by app code the moment the migration above ships — no read or write path touches it except that one migration function, once. Actual removal from the schema is deferred to a later release, once the consolidation migration has had time to run in the wild.

**Tests:** `GlobalShardConfigConsolidationMigrationTests` in `GlobalTrusteeDepthTests.swift` (migrates existing trustees to depth 0, deletes the row, idempotent, no-op when nothing exists), `PurgeCustody_CombinedTests.purgesAllThreeStoresInOnePass` (renamed from four to three stores in `ShardCustodyPurgeTests.swift`), `GroupModelTests.swift`'s `deleteContact_makesGlobalTrusteeDesignationUnreachable` (rewritten from the old `...purgesGlobalShardConfigTrustee` — confirms deletion needs no separate purge). The old `PurgeCustody_GlobalShardConfigTests` and `SaveGlobalShardConfigMergeTests` suites were removed — they tested methods that no longer exist.

### 4. New decoy-custodian display store — and a hard constraint on what it can contain

**Status: re-scoped, not yet implemented.** The original outline below called for the same padded-slot storage discipline item 3 originally proposed — that discipline turned out to be unnecessary for item 3 (see item 3 above) and is unnecessary here for the same reason: decoy custodians aren't existing entities you're marking, they're fabricated records created from scratch, which is structurally identical to how `VaultEntry` already works — many independent rows, each carrying its own exact-match depth stamp, no shared array, no slot count, no padding, no whole-scheme re-encryption on a single edit.

**Re-scoped design:** a new, minimal model — `DecoyCustodian` — with an encrypted display name, an encrypted shard-count, and an encrypted exact-match depth stamp (mirroring `VaultEntry.visibleThroughDepth`: visible only at the exact depth it was created for, never leaking into a shallower or deeper view). Sealed under `deriveShardCustodyKey()` like everything else in this system. Create as many rows as wanted at whatever depth, exactly like adding vault entries — no fixed count to plan around.

Confirmed `CustodyShard.Payload` (`CustodyShard+Model.swift:73-82`) still carries a real `SignedAttribute` — an actual owner-signed Shamir shard from a genuine protocol exchange, consumed by `handleInbound`/manifest reconciliation. This constraint from the original scoping is unchanged: a decoy entry cannot reuse `CustodyShard` without either crashing that reconciliation code or having fake data mistaken for recoverable material. `DecoyCustodian` has zero interaction with the real shard protocol — no `SignedAttribute`, no fingerprint, never touched by `handleInbound`.

**A constraint worth stating explicitly, not implied:** the decoy display name must be entirely fabricated — never a real contact's name, hidden or not. Reusing an actual hidden contact's identity as decoy-custodian "flavor text" would mean that contact's real name renders in the clear (once decrypted) at a duress depth specifically designed to keep them invisible — a direct, catastrophic leak of exactly the thing being protected, worse than anything else in scope here. Generation approach can be as simple as this system needs — a small fixed set of plausible display-name shapes is enough; this doesn't need the drafts feature's OS-dictionary/anti-fingerprinting rigor, since a person's name isn't trying to pass as typed prose.

### 5. Wiring the decoy store into `Vault+Tab.swift`

**Status: re-scoped, not yet implemented.** Confirmed still minimal against current code: `custodianRows` (`Vault+Tab.swift:453-484`, now filtered by `isDisplayable` per items 1-2) still produces a plain `{ownerIdentifier, ownerName, count}`-shaped row (`CustodianRow`) consumed by an unconditional `ForEach`, with no real-vs-decoy distinction baked into the row type or the rendering code. Once item 4's `DecoyCustodian` store exists, the only change needed is in assembly: concatenate the depth-filtered real rows with `DecoyCustodian` rows matching the exact current depth into one array before it reaches the `ForEach` — no new row view, no new template, `CustodianRow` doesn't even need a real-vs-decoy flag since the UI is deliberately meant to render both identically.

**Whether this is worth building — resolved, yes.** This was initially flagged as cosmetic plausibility rather than a data-leak fix, on the reasoning that an empty custody section only looks suspicious if compared against decoy vault entries elsewhere. That framing undersold the actual asymmetry. The real comparison isn't "empty vs populated" — both real and duress custody sections are commonly empty, since custody requires another person to have deliberately sent you their shard, a rare opt-in interaction. The asymmetry is *capability*: at depth 0, the section is empty today but *can* become non-empty tomorrow if a contact sends a shard. At every duress depth, right now, the section is *structurally incapable* of ever becoming non-empty — no code path can put anything there. That's not "commonly empty," that's "permanently empty by construction," and it's exactly the class of tell this doc closes everywhere else (U2's grace-period asymmetry, S6's nil/non-nil split, U5's snapshot gaps) — a coercer who understands the app, or who simply watches over time, would find a decoy layer that can never develop the one kind of content the real layer can.

**Alternative considered and rejected:** hiding the "Custodian Shards" section entirely at duress depths, rather than showing it empty. Worse, not better — a whole section disappearing is a far easier tell to notice than one list happening to be empty.

### Confirmed: real shards from safe contacts already get correct duress-depth visibility — nothing to build for this case

While scoping items 4–5, two assumptions about the current inbound path were checked directly against the code rather than taken on faith:

1. **A sensitive (non-safe) contact's bundle is blocked before it's ever decrypted while restricted.** Confirmed — `passSecurityControl` (`OccultaApp.swift:733`) throws `ContactManager.Errors.noPublicKeyToEncryptWith` when `security.isRestricted && !isSafeContact(identifier)`, and this runs immediately after sender identification (fingerprint match only) but **before** `openGroup`/`decryptSealed` are ever called — the ciphertext is never opened for a non-safe sender while restricted. Matches C1 in `forensic-trace-avoidance.md`.

2. **A safe contact's real shard-op bundle received at a duress depth fails to get added to custody.** Checked and found **incorrect**. `ShardCustodyManager.handleInbound`/`handleDistribute`/`handleReplace` (`ShardCustody+Manager.swift`) have no depth check anywhere, and `deriveShardCustodyKey()` is explicitly depth-independent (its own doc comment: "No LAContext needed... enables fully automatic shard operations on bundle receipt"). Storage succeeds unconditionally regardless of `Manager.Security.currentDepth`.

   Since `CustodyShard` carries no depth stamp of its own, `Vault+Tab.swift`'s display filter (items 1–2, already shipped) keys entirely off the *owner contact's* own ceiling (`Contact.Profile.visibleThroughDepth`, `value >= depth`). For a genuinely safe contact — ceiling covering both the duress depth it was received at and depth 0 — a stored shard is therefore **already** visible at the depth it arrived *and* at every shallower depth down to 0. This is exactly the "visible at this duress level and every level below it, down to the real layer" behavior that was being asked about — achieved for free by the existing contact classification, no new field or mechanism required.

   **Verified empirically, not just by static reading:** `OccultaTests/Vault/InboundShardCustodyDuressTests.swift` (new) —
   - `safeContactDistribute_atDuressDepth_storesAndStaysVisibleDownToDepthZero`: a safe contact (`visibleThroughDepth = Int.max`, matching production's real depth-0 stamp) sends a real, signed `.distribute` op while the device is at duress depth 1; the `CustodyShard` row is stored, and `isDisplayable` holds both at that duress depth and back at depth 0.
   - `sensitiveContactDistribute_atDuressDepth_storesButIsHiddenFromDisplay`: same op from a sensitive contact (`visibleThroughDepth = 0`) — storage still succeeds (confirming it really is unconditional, not accidentally gated some other way), but `isDisplayable` correctly returns `false` at the duress depth, confirming the display-time filter is what actually protects this, not a storage-time gate.

   Both pass. Full suite re-run showed one failure (`EncryptBundleShardFallbackTests.fallbackDropsAllThreeShardFields`), confirmed pre-existing/flaky and unrelated — passes cleanly in isolation.

**This is a distinct mechanism from item 4's `DecoyCustodian`, not a substitute for it.** The ceiling behavior above only applies to *real* content from a genuinely safe, pre-existing relationship — it inherits that contact's own classification, the same way `Contact.Profile.visibleThroughDepth` already works everywhere else. `DecoyCustodian` remains necessary for the separate, still-open problem items 4–5 solve: fabricated content at a duress depth with **no real relationship behind it** to inherit visibility from — which is exactly why that mechanism needs its own exact-match depth stamp rather than being able to piggyback on a contact's ceiling.

### A bigger, separate gap found while checking this: rejection itself is a live oracle — neither mechanism above touches it

Checking whether a coercer with a second device could defeat the ceiling behavior above (send a real shard, see if it's suppressed) surfaced something more fundamental than either item 4 or the ceiling finding addresses: `passSecurityControl` (`OccultaApp.swift:733`) rejects any bundle from a known, non-safe-at-this-depth contact with a visible, surfaced error, *before* decryption — and real mode has no equivalent rejection path for a genuinely known contact at all. A coercer who force-pairs or already controls one real contact identity can send anything and read the accept/reject outcome directly as a duress signal, independent of what's stored or displayed anywhere. Neither the safe-contact ceiling behavior nor `DecoyCustodian` changes this — both only govern what happens to content that's already past this gate; this attack never gets that far. Full write-up: `Docs/Bugs/v1.10.0/Non-Safe-Sender-Rejection-Is-A-Duress-Detection-Oracle.md` (also tracked as C3 in `forensic-trace-avoidance.md`). Open, unscoped — broader than shard custody, since `passSecurityControl` gates every bundle type the same way.

### Build order this implies
Items 1 and 2 (filtering + the merge-not-overwrite save fix) are independently useful and lower-risk — they close the live leak even with zero decoy content, and don't depend on anything else here. **Done** (`9e439e3`). Item 3 shipped as the simpler per-contact `globalTrusteeDepth` design, then fully consolidated (item 3a) — `GlobalShardConfig`'s own merge-not-overwrite save path (`saveGlobalShardConfig(mergingVisibleSelection:isVisible:)`) is now dead code, deleted, since each contact's field is independent and there's no flat list left to corrupt with a partial save. Items 1–2's `isDisplayable` filtering itself is untouched — both files still filter candidates by depth-visibility the same way, just against `globalTrusteeDepth` instead of a `GlobalShardConfig` fetch. **Items 4–5 are now fully re-scoped** (see above) — same exact-match-per-row pattern as item 3's final design, confirmed worth building, not yet implemented.

## Implementation status

**Done — Gap 1 only.**

- **`ShardCustodyManager.purgeCustody(for:)`** (`ShardCustody+Manager.swift`) — derives the shard-custody key once and reuses it across all four steps: deletes `CustodyShard` rows by `ownerContactIdentifier`, `PendingShardDistribute` rows by `contactIdentifier`, `PotentiallyLostShard` rows by `contactIdentifier` (all three: fetch, filter, delete — no existing by-contact deletion for the latter two, matching the doc's original plan), and removes the identifier from `GlobalShardConfig.trusteeIDs`, saving once at the end.
- **`GlobalShardConfig` is always resaved**, even when the deleted identifier was never a trustee and even when no `GlobalShardConfig` row existed at all before this call — a fresh row is created either way. This closes two related forensic signals: (a) which deletions actually removed a trustee, and (b) whether this user has ever configured Vault trustees at all (absence of any row would otherwise itself be a signal). Verified by `resavesUnconditionally_evenWhenIdentifierWasNeverATrustee` and `createsConfigRow_evenWhenNoneExistedBefore` in `ShardCustodyPurgeTests.swift`.
- **`ContactManager.deleteContact`** (`Contact+Manager.swift`) gained `vaultManager: VaultManager? = nil, shardCustodyManager: ShardCustodyManager? = nil` — optional, nil-safe, matching the `encryptGroupBundle`/`activateSecureMode` precedent. Calls `shardCustodyManager?.purgeCustody(for: identifier)` (errors propagate, matching how the existing group-purge step already behaves — the soft-delete itself has already been committed by this point regardless) then `vaultManager?.markShardsLost(forContact: identifier)` (existing function, no changes, inherits its existing "no-ops if vault is locked, deferred to next `.inquire` cycle" characteristic, flagged as a pre-existing gap in the original finding above, not something this fix closes).
- **Both UI call sites updated** (`Contact+Form.swift`, `ContactFormV2.swift`) to read `VaultManager`/`ShardCustodyManager` from `@Environment` (already injected at the app root, `OccultaApp.swift`) and pass them through.
- **Tests added:** `ShardCustodyPurgeTests.swift` (9 tests — per-store removal, cross-contact isolation, the two camouflage cases above, and a combined-pass test) plus one integration test in `GroupModelTests.swift` (`deleteContact_withShardCustodyManager_purgesGlobalShardConfigTrustee`) confirming `deleteContact` actually invokes `purgeCustody`, not just that `purgeCustody` behaves correctly in isolation.
- **Verified:** full `OccultaTests` suite — 613 passed, 0 failed, 0 regressions.

**Deliberate side effect worth knowing about:** because `GlobalShardConfig` is now always resaved on every contact deletion, **any user who deletes even one contact, ever, will end up with a `GlobalShardConfig` row in their database — even if they've never touched the Vault or trustee features at all.** This is the intended consequence of closing signal (b) above, not an oversight, but it's a real, permanent behavior change worth being aware of rather than discovering incidentally.

**Done — Gap 2, items 1–2 only (the live-leak fix, not the decoy machinery).**

- **`Vault+Tab.swift`'s custodian list** (`custodianRows`) now drops a row if its owner contact isn't `security.isDisplayable(_:)` at the current depth, and drops rows for an unresolvable owner identifier outside depth 0 (still falls back to "Unknown"/raw identifier at depth 0, matching prior behavior). The section's outer/inner "is this empty" checks were switched from the *unfiltered* `rawCustodyShards` to the *filtered* `custodianRows` — fixing a pre-existing dead-code bug where the empty-state text ("Shards appear here once you get one...") could never actually render, since the section's own outer guard already excluded that case. The section now always renders when `filter != .personal`, so its mere presence/absence can't itself be a tell.
- **`VaultGlobalTrustees.swift`'s picker** (`mlkemContacts`) is filtered the same way, and `loadConfig()` seeds `selectedIDs` from only the currently-visible subset of the stored `trusteeIDs`.
- **The merge-not-overwrite save fix landed as a new method on the manager, not inline in the view** — `ShardCustodyManager.saveGlobalShardConfig(mergingVisibleSelection:isVisible:)` (`ShardCustody+Manager.swift`) fetches the current full `trusteeIDs`, preserves every identifier `isVisible` reports as not-currently-visible untouched, and replaces the rest with the caller's edited selection. Moved out of the view specifically so it's unit-testable — a `private func save()` inside a SwiftUI view isn't reachable from a test without UI hosting, and this is exactly the kind of logic (a duress-depth save silently deleting every hidden trustee) worth having a real test for, not just a code-reviewed view method.
- **Tests added:** `ContactDepthVisibilityTests` (3 tests) — `Manager.Security.isDisplayable(_:)`/`isVisible(_:atDepth:)` had no direct test coverage of its own before this, despite being reused as the security-relevant gate in both of the above; covers safe (`Int.max`, visible everywhere), sensitive-at-depth-D (visible through D, hidden beyond), and unclassified (nil `visibleThroughDepth`, visible everywhere). `SaveGlobalShardConfigMergeTests` (3 tests) — hidden trustees survive a visible-only edit, merging into an empty config just writes the selection, an unresolvable stored identifier is preserved by default.
- **Verified:** full `OccultaTests` suite — 624 passed, 1 failed (confirmed flaky and unrelated — `VaultManagerLifecycleTests.locksAfterInactivity`, a 0.05s timing-sensitive test that passes in isolation), 0 regressions.

**Not done:** Gap 2 items 3–5 (the actual per-depth decoy machinery: `GlobalShardConfig`'s schema change, the new decoy-custodian store, wiring it into `Vault+Tab.swift`) — per "Build order this implies," these were always scoped as a separate, bigger undertaking to tackle only once 1–2 were done and confirmed safe. Nothing else changed here.

---

## Duress signaling for shard custody — explored, item 3 found unsafe as specified

A follow-on spec, proposed while scoping items 4–5, with three requirements:

1. No shards from sensitive/hidden contacts may be shown in duress; if held, their *existence in the database* must be camouflaged against forensic investigation, not just hidden in the UI.
2. Shard operations (receive, distribute, status updates) must behave identically under duress and at rest — no observable difference that could itself signal "this session is a duress session."
3. Receiving a shard from (or distributing one to) a contact under duress should covertly inform that contact's owner that the exchange happened under duress — the outbound bundle carries a signal.

**Status: item 1's full DB-camouflage is separately scoped, bigger, and still not implemented — but its low-lift diff-comparison slice is done. Item 2 is verified, not just assumed. Item 3 is not currently buildable safely and is not going to be pursued as specified.**

### Item 1 — DB-level camouflage of shard existence

**Full fix: not implemented, separately scoped, bigger than items 4–5.** `CustodyShard`'s own model comment already documents the residual gap: the shard-custody key is Secure Enclave-protected but not depth-gated, so raw DB access on an unlocked device can already decrypt any row, real or sensitive-contact-owned — UI hiding (items 1–2, shipped) never touched that. Actually camouflaging existence, not just visibility, means choosing "Design B" for shards where `forensic-trace-avoidance.md` S5 already chose (and documented as an accepted trade-off) "Design A" for contacts: pulling sensitive rows out of the main DB into the activation blob (`LayerPayload`/`LayerContact`, which already exists and already does this for contacts) during activation, restoring them on deactivation. Architecturally feasible — the infrastructure exists — but means extending `Manager+Security.swift`'s Step 4/5 activation/deactivation logic, already carefully tuned and tested. Row *count* and the derivable-key decryption gap are unaffected by anything below and remain open, matching the accepted-gap precedent of S5/S8.

**Low-lift slice: implemented.** `purgeCustody(for:)` (`ShardCustody+Manager.swift`) now re-seals every *surviving* row in `CustodyShard`, `PendingShardDistribute`, and `PotentiallyLostShard` with a fresh nonce (same content) on every purge, not just the rows being deleted — closing the diff-comparison tell where a raw-DB examiner comparing two snapshots across a deletion could otherwise see exactly which rows disappeared and find every surviving row byte-for-byte identical. Reuses the key already derived for the purge; rows that fail to decrypt are left untouched, same as before. Doesn't achieve existence-camouflage (that's the full fix above) — closes the cheaper temporal-diff angle only. **Tests:** `survivingShardGetsFreshCiphertext_contentPreserved`, `survivingQueuedDistributeGetsFreshCiphertext_contentPreserved`, `survivingWatchRowGetsFreshCiphertext_contentPreserved` (`ShardCustodyPurgeTests.swift`) — one per store, each confirms ciphertext bytes change while decrypted content (owner/contact identity) stays the same.

### Item 2 — Shard operations work normally under duress

**Implemented — verified, not just assumed.** Checked directly: neither `ShardCustody+Manager.swift` nor `Vault+Manager+Shards.swift` (the actual distribute/receive/`prepareShards` code) references `currentDepth`, `isDisplayable`, or `isSecureModeActive` anywhere — no hidden depth-0 assumption exists to remove. The shard protocol (`SHARD_PROTOCOL_CASES.md`) also piggybacks `shardOperations`/`custodyManifest`/`expectedShards` on whatever `SealedPayload` bundle is sent next for any reason — there's no dedicated "shard received, sending confirmation now" round-trip to begin with, so receiving a shard doesn't introduce a new, distinguishable network event either. **Test:** `DecoyShardDistributionTests.decoyEntry_duressTrustees_prepareShardsAndQueueDistribute_worksAtDuressDepth` proves the full chain end-to-end — a decoy vault entry stamped at a duress depth, two contacts marked global trustees at that exact depth (item 3's `globalTrusteeDepth`), `prepareShards`, and `queueDistribute` all succeed, producing real `PendingShardDistribute` rows, with the app at `currentDepth == 1` throughout.

### Item 3 — Covert duress signal on accept/distribute: found unsafe

**The vulnerability.** The signal was scoped to fire for "a safe contact" — any contact currently displayable at the active depth. That criterion is exactly backwards under an adversarial coercion session: a coercer who sets up a new device and forces the victim to pair with it (e.g. to "prove the app works normally") makes that device a safe contact at the current depth the moment pairing completes. The coercer is then the legitimate, intended recipient of any bundle sent to that contact — no interception or cryptanalysis needed, they decrypt it the ordinary way, including whatever duress flag rides inside. The app would be handing the coercer direct, app-signed proof that the victim tried to signal for help, in a scenario where that discovery could escalate to violence. This is a disqualifying flaw, not a tuning issue — "currently safe/displayable" can be manufactured on demand by the exact adversary the feature exists to defend against.

**Mitigation considered:** restrict signal-eligible recipients to contacts with a real, pre-existing shard-custody relationship (an actual `CustodyShard`/`ShardRecord` predating the current session, established at real depth 0), and make that eligibility state read-only outside depth 0 so it can't be manufactured retroactively during a coercion session either. This closes the "coercer sets up a fresh phone" attack specifically — a freshly-added contact has no such history.

**Rejected.** Explicit decision: pre-existing relationships do not get a pass. A contact with a genuine, real shard-custody relationship established before any coercion began can still *be*, or *become*, the coercer — an abusive partner or family member the user trusted with a real recovery role in the past is not excluded by "has history," and the mechanism would still hand that person the same proof if they're the one holding the phone later. No boundary drawn purely on relationship age or shard history closes this — the fundamental problem is that *any* recipient, however chosen, is a future compromise surface the app cannot vet at signal-composition time.

**Conclusion: no known safe design for this requirement.** Not scoped further, not being built. If revisited, it needs a fundamentally different approach — not a narrower recipient filter — and should be treated as an open, unsolved problem rather than a deferred implementation detail.

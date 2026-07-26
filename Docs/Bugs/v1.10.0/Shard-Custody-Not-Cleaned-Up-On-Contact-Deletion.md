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

## Scoping the fix for Gap 1 (contact deletion) — Gap 2 stays explicitly out of scope

**Status: scoped, not yet implemented — one open question deferred, blocks implementation.** Verified against the actual plumbing before writing this — the drafts fix had one mature `Message.Draft.purge` to lean on; this one has four different data models with different owners and no equivalent single precedent, so each piece needed checking rather than assuming. See "Deferred, not investigated" below before starting on `GlobalShardConfig`.

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

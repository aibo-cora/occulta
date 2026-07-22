# Shard custody data is never cleaned up — on contact deletion, or on Secure Mode activation

**Status:** confirmed, not fixed. Found while investigating a separate, smaller gap (`Message.Draft` not purged on contact deletion — see `Docs/Features/Message Persistence/FINDINGS.md`, "Investigated: does `reKeyOrPurgeAll`'s `isKnownContact` check let an already-hidden contact's orphaned draft survive?").

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

## Not yet scoped or fixed

This document records the finding only. No design for a fix has been discussed — unlike the `Message.Draft`/`deleteContact` gap, this touches multiple SwiftData models with no existing cleanup precedent to extend, and needs its own dedicated investigation into what "purge shard custody for a deleted/duress-hidden contact" should even mean (e.g., does deleting a trustee need to trigger re-splitting the secret with a smaller `k`/`n`? does an owner's `CustodyShard` need explicit secure deletion, not just a status flag?) before any implementation is attempted.

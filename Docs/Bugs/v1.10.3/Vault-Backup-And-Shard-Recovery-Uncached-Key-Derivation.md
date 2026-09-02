# Uncached Secure Enclave key derivation, again — vault backup staleness and shard recovery, the predicted third and fourth instances

**Status: fixed and verified — `44621ef`, `b4ad1ab`, `61e3a63`, `fca83f6`.** `Vault-Shard-Setup-Severe-Hang-From-Uncached-Per-Row-Vault-Key-Derivation.md`'s own "Why this wasn't caught by the sibling bug's fix" section predicted this: *"No general 'derive once, cache for the duration of a screen' convention exists in this codebase to prevent a third instance of the same pattern elsewhere."* A code review of `release/v1.10.3` found three more — `refreshBackupStaleness` (O(N) Enclave derivations per vault entry), `acceptReturnedShard`'s recovery-buffer-key chain (~5 derivations per incoming shard), and `attestation(for:)`'s per-shard owner-key lookup. A self-review of the fix itself then found three more *incomplete* applications of the fix within the same diff — closed those too.

## Symptom

None of these were reported as a user-visible hang like the sibling bug — they were found by code review, not an Instruments trace. But the shape and mechanism are identical: a function that redundantly re-derives the same Secure Enclave key once per loop iteration or once per call in a short chain, instead of once for the whole operation.

## Measured cost

Benchmarked directly against the real `Manager.Key().createHybridLocalEncryptionKey()` path (Secure Enclave is real on Apple Silicon Simulator, confirmed by this repo's own testing notes in `CLAUDE.md`):

```
n=1   total=5.5ms   avg=5.5ms   (first call pays one-time SEP session setup)
n=10  total=27.9ms  avg=2.79ms
n=50  total=93.0ms  avg=1.86ms
n=100 total=172.1ms avg=1.72ms
n=200 total=436.8ms avg=2.18ms
```

Steady state: **~2ms per derivation.** Not catastrophic per call, but every one of the chains below pays it multiple times for what is provably the same key within one operation.

## Root cause 1 — `refreshBackupStaleness`: O(N) derivations, one per vault entry

Recently changed from an O(1) SwiftData `fetchCount` to `entriesVisible(atDepth:).count` (a correctness fix for depth-scoping — see the sibling doc on the nil-handling bug this same function was involved in), which decrypts every entry's depth stamp to filter by visibility. `Data.decrypt()` re-derives the local DB hybrid key via a fresh Enclave round trip on every call, with no caching — so counting entries costs one derivation per entry instead of zero. This runs on the main actor, on every unlock and every Vault tab appearance ([Vault+Tab.swift](../../../Occulta/UI/Tabs/Vault/Vault+Tab.swift), both `.onChange(of: isUnlocked)` and `.onAppear` — can fire twice per tab visit).

**Fix (`44621ef`):** `VaultEntry` gained `isVisible(atDepth:whenUnclassified:usingKey:)` ([Vault+Model.swift:279](../../../Occulta/Features/Vault/Vault+Model.swift)), mirroring the pre-existing `Contact.Profile.isVisible(atDepth:usingKey:)` convention. `entriesVisible(atDepth:)` ([Vault+Manager+Backup.swift:253](../../../Occulta/Features/Vault/Vault+Manager+Backup.swift)) derives the key once and reuses it across the filter — O(N) Enclave round trips collapses to O(1) Enclave + O(N) cheap in-memory AES-GCM opens.

## Root cause 2 — `acceptReturnedShard`: ~5 derivations per incoming shard

Every function in the recovery-buffer chain independently called `self.keyManager.deriveRecoveryBufferKey()` — none threaded a derived key to the next call, despite it being the same key throughout one shard delivery:

```
acceptReturnedShard
 └─ storeRestoreShard          — 3 derivations internally (dup-check, insert, count)
 └─ attemptBEKRestore
     └─ loadRestoreShards      — 1 derivation
     └─ clearBEKRestoreShards  — 1 derivation, only on success
```

**Fix (`b4ad1ab`):** added `usingKey:` variants of the private helpers (`decryptAllReconstructShards`, `insertReconstructRow`, `bekRestoreRows`) plus the two functions `attemptBEKRestore` calls across both its branches (`loadRestoreShards`, `clearBEKRestoreShards` — these two had to drop `private` since `attemptBEKRestore` lives in a different file, `Vault+Manager+Backup.swift`). None of the existing public signatures changed — `storeRestoreShard`, `loadRestoreShards`, `clearBEKRestoreShards`, `attemptBEKRestore`, `cancelReconstruction`, and `acceptReturnedShard` are each called independently by ~30 test call sites and by `ShardCustody+Manager.swift`, so a required new parameter on any of them wasn't an option. Each entry point now derives once internally and threads the result through its own body. `storeRestoreShard`: 3 → 1. `attemptBEKRestore`: up to 2 → 1.

## Root cause 3 — `attestation(for:)`: owner-key lookup repeated per shard, not per owner

`ShardCustody+Manager.swift`'s `mismatchHandbackOps` maps every mismatched shard through `attestation(for:)`, and every candidate in that map already shares the same owner (the caller filters on `contactIdentifier` before building the list) — but `attestation(for:)` re-fetched the owner's `Contact.Profile` and re-decrypted its retained public keys, searching for a fingerprint match, on every single call.

**Fix (`61e3a63`):** `mismatchHandbackOps` now resolves every one of the owner's retained keys once, decrypted and indexed by fingerprint (`retainedKeysByFingerprint(forOwner:)`, [ShardCustody+Manager.swift:412](../../../Occulta/Features/Vault/ShardCustody+Manager.swift)), before mapping. `attestation(for:retainedKeysByFingerprint:)` ([:461](../../../Occulta/Features/Vault/ShardCustody+Manager.swift)) becomes a dictionary lookup plus the one part that's genuinely per-shard: signing a hash unique to that shard's attestation. Keyed by fingerprint rather than a single cached key, since buffered shards can span more than one past owner-key rotation and each must verify against its own stamped fingerprint, not just the most recent one.

## Residual: a self-review found three more incomplete applications, within this very fix

A second code-review pass, scoped specifically to this diff, found the correctness side clean but three places where the pattern above had been applied incompletely — a redundant derivation sitting immediately next to a fix that had already eliminated the identical pattern in the same function:

- **`acceptReturnedShard`'s per-entry branch** derived the recovery buffer key for its own dup-check and insert, then called `tryFinalizeReconstruction`, which independently re-derived the identical key two lines later. Added `tryFinalizeReconstruction(entryID:usingKey:)` ([Vault+Manager+ReturnBuffer.swift:119](../../../Occulta/Features/Vault/Vault+Manager+ReturnBuffer.swift)); the no-key public version now delegates to it instead of duplicating the derive-then-decrypt logic.
- **`migrateLegacyRestoreShardFile`** derived its own key even though both its callers (`storeRestoreShard`, `loadRestoreShards(usingKey:)`) already derive or hold that same key immediately around the call site. It now takes the key as a required parameter ([:357](../../../Occulta/Features/Vault/Vault+Manager+ReturnBuffer.swift)); `storeRestoreShard` was reordered to derive its key before migrating instead of after.
- **`buildShardOperations`** derived the shard custody key twice per call — `pendingDistributeOps` and `mismatchHandbackOps` each independently derived it, even though a keyed overload (`decryptAllCustodyShards(using:)`) already existed in the file *before* this session's changes. `buildShardOperations` ([ShardCustody+Manager.swift:343](../../../Occulta/Features/Vault/ShardCustody+Manager.swift)) now derives once and threads it to both halves. This one is called once per group member when encrypting a group bundle, so the fix scales with group size.

Fixed in `fca83f6`.

**One flagged trade-off, deliberately left unchanged:** `retainedKeysByFingerprint` now decrypts every one of the owner's retained keys up front, where the original per-shard code used a lazy `first { }` search that could stop at the first fingerprint match. For a single shard whose matching key happens to be first in the list, this is marginally more Enclave work than before. Reverting to lazy search would reintroduce the per-shard repeated search this fix targets for the common multi-shard case, in exchange for a small saving in the rare single-shard, early-match case. Not changed.

## Still open

The core observation from the original hang doc stands: **there is still no general "resolve this key once for the duration of this operation" mechanism in this codebase.** This fix is the third and fourth confirmed instance of the same bug shape (`VaultEntry.isVisible(atDepth:usingKey:)`, `ReturnBuffer`'s five keyed-overload pairs, `ShardCustody+Manager`'s `attestation`/`buildShardOperations` threading — now four independent hand-written instances of the identical wrapper pattern, alongside the pre-existing `Contact.Profile.isVisible(atDepth:usingKey:)`). A fifth instance elsewhere in the codebase remains exactly as likely as this one was, and the display path (`Vault+Tab.visibleEntries`, still calling the unkeyed `isVisible` once per entry per render while in duress mode) is a known, not-yet-fixed candidate for it — out of scope here since it long predates this session's changes and wasn't part of what this diff touched, but worth knowing about if a future hang report points back at the Vault tab.

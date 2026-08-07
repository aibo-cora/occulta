# Opening a vault entry's "Manage Shards" screen causes a severe hang — two separate uncached key derivations, redundantly re-run across the view's computed properties

**Status:** open, partially scoped, not implemented. Found via an Instruments trace showing an 11-second hang when opening `VaultShardSetup` from a vault entry's detail view, with only 3 eligible ML-KEM contacts — disproportionate to contact count, which pointed at a fixed cost beyond the trustee-row loop (see "The multiplier" below). Root cause identified by code reading. Same anti-pattern as the already-fixed `Group-Reencryption-Multi-Second-Block-On-Visibility-Toggle.md` (uncached SE/Keychain key derivation, paid many times over per screen instead of once), independently reintroduced here — and worse, in **two** separate uncached-key call chains, not one. **Correction:** the original pass below traced only the vault key; a second, likely larger contributor — the local-DB hybrid key, reached via the generic `Data.decrypt()` used for contact names and classification fields — was found afterward and is probably the dominant cost, since it scales with *total* contact count, not just eligible ones. See "A second, likely larger cost" below. The "Scoped fix" section only covers the vault-key half; the local-DB-key half has no proposed fix yet.

## Symptom

Tapping "Manage Shards" from a vault entry's detail view (`VaultEntryDetail.actionStrip`, [Vault+EntryDetail.swift:363-367](../../../Occulta/UI/Tabs/Vault/Vault+EntryDetail.swift)) pushes `VaultShardSetup(mode: .entry(entry.id))`. Instruments shows a severe hang on this transition — no loading state, no re-tap guard, the same class of unresponsive-UI symptom the visibility-toggle bug had before its UX mitigation.

**Reported: 11 seconds with only 3 eligible ML-KEM contacts.** Notably disproportionate to contact count — see "The multiplier" below, which turned out to be dominated by something other than the trustee-row count.

## Root cause: the vault key is re-derived from scratch on every access to `distributionMeta`, and `distributionMeta` is read once per trustee row

### The call chain, one hop at a time

1. **`trusteesCard`** iterates every ML-KEM-eligible contact and renders a `trusteeRow` for each ([Vault+ShardSetup.swift:282-287](../../../Occulta/UI/Tabs/Vault/Vault+ShardSetup.swift)):
   ```swift
   ForEach(Array(mlkemContacts.enumerated()), id: \.element.identifier) { idx, contact in
       trusteeRow(contact)
       ...
   }
   ```

2. **`trusteeRow(_:)`** looks up that contact's shard status via `shardRecord(for:)` ([:294-299](../../../Occulta/UI/Tabs/Vault/Vault+ShardSetup.swift)):
   ```swift
   let record = shardRecord(for: contact.identifier)
   ```

3. **`shardRecord(for:)`** reads `distributionMeta` ([:538](../../../Occulta/UI/Tabs/Vault/Vault+ShardSetup.swift)):
   ```swift
   distributionMeta?.shards.first { $0.contactIdentifier == contactIdentifier }
   ```

4. **`distributionMeta`** is a plain computed property — no caching, re-evaluated every time it's read ([:561-570](../../../Occulta/UI/Tabs/Vault/Vault+ShardSetup.swift)):
   ```swift
   private var distributionMeta: ShardDistributionMetadata? {
       switch mode {
       case .entry(let id):
           _ = self.vaultEntries
           return try? self.vault.shardDistributionMetadata(for: id)
       ...
   ```

5. **`VaultManager.shardDistributionMetadata(for:)`** calls `self.currentKey()` before it can decrypt anything ([Vault+Manager+Shards.swift:140-147](../../../Occulta/Features/Vault/Vault+Manager+Shards.swift)):
   ```swift
   func shardDistributionMetadata(for entryID: UUID) throws -> ShardDistributionMetadata? {
       guard let entry  = try self.fetchEntry(by: entryID) else { return nil }
       guard let cipher = entry.shardDistributionEncrypted else { return nil }
       let vaultKey = try self.currentKey()
       ...
   ```

6. **`currentKey()`** has no memoization anywhere in `VaultManager` — every call re-derives ([Vault+Manager.swift:363-383](../../../Occulta/Features/Vault/Vault+Manager.swift)):
   ```swift
   func currentKey() throws -> SymmetricKey {
       guard let ctx = self.authContext else { throw VaultError.locked }
       guard let key = try self.keyManager.deriveVaultKey(context: ctx) else { ... }
       self.resetInactivityTimer()
       return key
   }
   ```

7. **`deriveVaultKey(context:)`** is the expensive part — a Keychain query against the Secure Enclave, a full ECDH key exchange, and an HKDF derivation, every single call, no cache ([Key+Manager.swift:716-741](../../../Occulta/Services/Key+Manager.swift)):
   ```swift
   func deriveVaultKey(context: LAContext) throws -> SymmetricKey? {
       guard let vaultPriv = try self.retrieveVaultPrivateKey(context: context) else { return nil }
       ...
       let rawSecret = SecKeyCopyKeyExchangeResult(
           vaultPriv, .ecdhKeyExchangeCofactorX963SHA256, fixedPubKey, ...
       ) as? Data
       ...
       return HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: rawSecret), ...)
   }
   ```
   `retrieveVaultPrivateKey(context:)` itself is a `SecItemCopyMatching` call scoped to `kSecAttrTokenIDSecureEnclave` ([Key+Manager.swift:682-705](../../../Occulta/Services/Key+Manager.swift)) — a real Keychain/SE round trip, not a local lookup.

No biometric re-prompt is involved — `authContext` is an already-authenticated `LAContext` from when the vault was unlocked, reused across calls. The cost is pure Keychain/SE latency, paid fresh every time, exactly matching what the visibility-toggle bug found for `Data.encrypt()`/`Data.decrypt()`.

### The multiplier — dominated by the CTA bar, not the row count

`distributionMeta` isn't read only from the per-row path. `hasExistingDistribution` ([:67](../../../Occulta/UI/Tabs/Vault/Vault+ShardSetup.swift)) reads it independently:
```swift
private var hasExistingDistribution: Bool { distributionMeta != nil }
```
and feeds two more computed properties, `ctaTitle` and `ctaEnabled` ([:73-80](../../../Occulta/UI/Tabs/Vault/Vault+ShardSetup.swift)) — each their own fresh, uncached evaluation.

**Correction to the original count above:** the naive assumption was "N contacts → roughly N derivations." That undercounts badly, because `ctaTitle`/`ctaEnabled` aren't read once each — they're read repeatedly as inline ternaries inside `ctaBar`'s view modifiers ([:463-475](../../../Occulta/UI/Tabs/Vault/Vault+ShardSetup.swift)):
```swift
Text(ctaTitle)                                                               // read 1 (ctaTitle)
.foregroundStyle(ctaEnabled ? .white : Color.secondary)                      // read 2 (ctaEnabled)
.background(ctaEnabled ? Color.occultaAccent : Color(.secondarySystemFill))  // read 3 (ctaEnabled)
.shadow(color: ctaEnabled ? Color.occultaAccent.opacity(0.27) : .clear, ...) // read 4 (ctaEnabled)
.disabled(!ctaEnabled || marking)                                            // read 5 (ctaEnabled)
```
Swift does not memoize a computed property across separate lexical call sites — each of these 5 reads independently re-walks `ctaTitle`/`ctaEnabled` → `hasExistingDistribution` → `distributionMeta` → the full Keychain/SE/HKDF chain. That's **5 full derivations from the CTA bar alone, fixed, regardless of how many contacts exist** — plus 1 more per `trusteeRow`.

For the reported case (3 contacts): 5 (CTA bar) + 3 (rows) = **8 independent full key derivations per single `body` evaluation**, and SwiftUI does not evaluate `body` exactly once per appearance — `@State` settling from `seedInitialState()` (called `.onAppear`) and the push-transition's own layout passes multiply this further. This is why the hang doesn't scale the way contact count alone would suggest: the fixed CTA-bar cost is comparable to or larger than the per-row cost even at N=3, and would still be present even with zero eligible contacts. Unlike the visibility-toggle bug, there's no batch re-encryption loop here — the cost is entirely from calling the same expensive, uncached derivation redundantly, many times, for data that doesn't change within a single screen visit.

## A second, likely larger cost: the local-DB hybrid key, uncounted above

The trace above only followed the vault key. There's a second, independent, uncached key involved on this same screen, and it likely dominates the 11-second total rather than the vault key.

### The key

The generic `Data.decrypt()` extension — used for `visibleThroughDepth`, `globalTrusteeDepth`, `givenName`, `familyName`, and every other encrypted contact field — calls `Manager.Crypto().decrypt(data:)` ([Crypto+Manager.swift:67-79](../../../Occulta/Services/Crypto+Manager.swift)):
```swift
func decrypt(data: Data?) throws -> Data? {
    guard let data, let key = try self.keyManager.createHybridLocalEncryptionKey() else { return nil }
    ...
}
```
`createHybridLocalEncryptionKey()` is the exact function the sibling bug (`Group-Reencryption-Multi-Second-Block-On-Visibility-Toggle.md`) found to be *more* expensive per call than the vault key's own derivation — two separate Keychain lookups, one SE ECDH exchange, and a third Keychain lookup for the random component, no caching. That fix explicitly scoped itself to `cleanUpGroupDuressMembership`'s batch path and left the generic `Data.decrypt()` extension untouched, by its own admission: *"the extensions used at dozens of other call sites app-wide — stay untouched."* This screen is one of those untouched call sites.

### Where it's hit, and why it scales with total contact count — not just the 3 eligible ones

`mlkemContacts` filters starting from `allContacts`, not from a pre-filtered set ([Vault+ShardSetup.swift:50-54](../../../Occulta/UI/Tabs/Vault/Vault+ShardSetup.swift)):
```swift
private var mlkemContacts: [Contact.Profile] {
    allContacts
        .filter { self.security.isDisplayable($0) }   // 1 local-DB decrypt PER CONTACT in the whole address book
        .filter { ... quantumKeyMaterialEncrypted != nil }  // free, no decrypt
}
```
`isDisplayable` decrypts `visibleThroughDepth` via `Data.decrypt()` ([Manager+Security.swift:1330-1336](../../../Occulta/Features/SecureMode/Manager+Security.swift)) — one full derivation per contact, every time `mlkemContacts` is read. It's an uncached computed property, read from at least:
- `trusteesHeader`'s count ([:266](../../../Occulta/UI/Tabs/Vault/Vault+ShardSetup.swift))
- `trusteesCard`'s `.isEmpty` check and the `ForEach` build ([:275, 282](../../../Occulta/UI/Tabs/Vault/Vault+ShardSetup.swift))
- the divider-count check *inside* the loop body, `idx < mlkemContacts.count - 1` ([:284](../../../Occulta/UI/Tabs/Vault/Vault+ShardSetup.swift)) — one more read per row
- `selected` ([:56-58](../../../Occulta/UI/Tabs/Vault/Vault+ShardSetup.swift)), which wraps it and is itself read from `k` (4 render-path reads: both stepper buttons, the threshold text, the canMark-block text) and `canMark` (6 render-path reads: `ctaEnabled`'s 4 ternaries route through it, plus `summaryCard` and `ctaBar` each check it separately) and directly in `summaryCard` (`selected.isEmpty`, `.count` at multiple points)

Counting only distinct source-level read sites (not SwiftUI's extra re-render passes): roughly **16 full contact-list scans per render**, each costing one local-DB-key derivation *times total contact count*, eligible or not.

`globalTrusteeIDs` ([:46-48](../../../Occulta/UI/Tabs/Vault/Vault+ShardSetup.swift)) is a separate uncached property, worse per call — `globalTrusteeIdentifiers()` decrypts **two** fields (`isDisplayable` and `globalTrusteeDepth`) for every contact in the address book. Read once per trustee row for the "GLOBAL" badge check ([:329](../../../Occulta/UI/Tabs/Vault/Vault+ShardSetup.swift)) — 3 more full-address-book double-scans for 3 rows.

`trusteeRow` also decrypts `givenName`/`familyName` directly per row ([:295-296](../../../Occulta/UI/Tabs/Vault/Vault+ShardSetup.swift)) — a flat 2 × 3 = 6 derivations, independent of address book size.

### Why this likely dominates the vault-key cost

The vault-key side is bounded at 8 derivations regardless of address book size (5 CTA bar + 3 rows). The local-DB-key side scales with *total* contact count — for an address book of, say, 20–30 contacts, the `mlkemContacts`/`selected`/`k`/`canMark` chain alone is on the order of 16 × 25 ≈ 400 derivations, plus 3 × 2 × 25 ≈ 150 from `globalTrusteeIDs`, plus 6 flat — north of 550 local-DB-key derivations, each arguably more expensive per call than the vault key's own. This plausibly dwarfs the vault-key contribution and better explains an 11-second hang from just 3 *eligible* contacts than the vault key alone did — the eligible count was never the right variable to look at; total address book size is.

**Not yet measured:** actual total contact count on the device that produced the 11-second trace, and a real per-call timing baseline for `createHybridLocalEncryptionKey()` to convert derivation counts into an expected wall-clock figure. Without those two numbers this section bounds the problem rather than pins it down exactly.

## Why this wasn't caught by the sibling bug's fix

The visibility-toggle fix (`Group-Reencryption-Multi-Second-Block-On-Visibility-Toggle.md`) scoped its change to `Data.encrypt()`/`Data.decrypt()`'s local-DB key path (`createHybridLocalEncryptionKey()`), which is a separate SE key entirely from the vault key (`deriveVaultKey`) used here. The two paths share the same *shape* of bug — an expensive, uncached per-call SE/Keychain derivation invoked once per list item — but are different code, so fixing one didn't touch the other. No general "derive once, cache for the duration of a screen" convention exists in this codebase to prevent a third instance of the same pattern elsewhere.

## Scoped fix (vault key only — local-DB key below is a separate, unscoped problem)

Lower-risk than the sibling bug's fix, because the expensive part (the `SymmetricKey` itself) never needs to leave `VaultManager` or be threaded through the View at all. What's actually worth caching at the View layer is `distributionMeta`'s *decrypted result* — `ShardDistributionMetadata`, plain bookkeeping data (contact IDs, shard status, threshold) this screen exists to display, not key material. So unlike the sibling fix, there's no `SymmetricKey`-lifetime reasoning to work through here; the key still only lives for the duration of one `deriveVaultKey` + `AES.GCM.open` call, exactly as today — the only change is calling that pair far less often.

**Shape of the change:**
- Replace the computed `distributionMeta` property with a `@State private var distributionMeta: ShardDistributionMetadata?`, populated by a new `refreshDistributionMeta()` method instead of recomputed on every read.
- Call `refreshDistributionMeta()` once in `seedInitialState()` (already wired to `.onAppear`).
- Add `.onChange(of: self.vaultEntries)` / `.onChange(of: self.bekRows)` on the view, each calling `refreshDistributionMeta()` — this is what preserves the *existing, intentional* reactivity documented on the current computed property ("re-renders whenever VaultEntry or BackupEncryptionKey changes in the persistent store, e.g. when `processInboundManifest` confirms a shard"). Losing this would be a real regression, not just a missed optimization, if the naive fix were "populate once in `onAppear` and never again."
- All existing read sites (`hasExistingDistribution`, `shardRecord(for:)`, the two direct reads in `markForDistribution`) stay textually unchanged — they'd just be reading a cheap stored property instead of triggering a derivation.

**One correctness subtlety, not just a perf one:** two call sites read `distributionMeta` *immediately after a local mutation* that changes the underlying encrypted field — `markForDistribution()` right after `performPrepareShards()`, and `revokeShard()` right after `updateShardStatus()`. `@Query`'s own propagation isn't guaranteed to have landed synchronously by that point, so relying solely on `.onChange(of: vaultEntries)` for those two spots risks reading stale cached data on the very next line. Both need an explicit `refreshDistributionMeta()` call right after their mutation, not just reliance on the `@Query` watcher.

**Why not cache the `SymmetricKey` itself instead:** would require exposing raw key material to the View layer, which the current architecture deliberately doesn't do — `VaultManager` derives and consumes the key internally, in one call. Caching the already-decrypted application data is both simpler and keeps that boundary intact.

## Not yet done

- **Implementation of either fix.** Both sections above are designs, not diffs — no code has been changed for this bug.
- **A fix for the local-DB-key side at all.** The vault-key scoped fix above doesn't touch `mlkemContacts`, `selected`, `k`, `canMark`, or `globalTrusteeIDs` — likely the larger contributor per "A second, likely larger cost" above. Same underlying shape of problem (uncached expensive derivation, read from many redundant call sites), but a different key, a different call chain, and scales with a different variable (total contact count, not row count) — needs its own scoping pass, not assumed to be solved by the vault-key fix.
- **Total contact count on the device that produced the 11-second trace**, and a real per-call timing baseline for `createHybridLocalEncryptionKey()` — the two numbers needed to convert the local-DB-key derivation-count bound into an actual expected wall-clock contribution, rather than leaving it as "likely dominates."
- **Per-derivation wall-clock cost for the vault key.** 11 seconds ÷ 8 known vault-key derivations (5 CTA bar + 3 rows) ≈ 1.4s each if `body` evaluated exactly once and the local-DB key contributed nothing — almost certainly wrong now that a second, likely larger cost is known to exist. This estimate should be treated as stale; a real isolated trace of both `deriveVaultKey` and `createHybridLocalEncryptionKey` is needed to apportion the 11 seconds between them.
- **On-device confirmation either fix collapses the hang**, once implemented — Secure Enclave is unavailable on Simulator, so, matching the sibling bug's own unresolved item, the actual wall-clock improvement needs a real device re-trace.

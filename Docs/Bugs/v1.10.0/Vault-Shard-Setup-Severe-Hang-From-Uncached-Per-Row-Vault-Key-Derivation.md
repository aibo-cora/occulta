# Opening a vault entry's "Manage Shards" screen causes a severe hang — two separate uncached key derivations, redundantly re-run across the view's computed properties

**Status: fixed and verified on-device — 11s → 1.02s.** Found via an Instruments trace showing an 11-second hang when opening `VaultShardSetup` from a vault entry's detail view, with only 3 eligible ML-KEM contacts. Root-caused to two independent uncached key derivations (vault key and local-DB hybrid key, see below), each redundantly re-run many times per render instead of once. Fixed in three commits, each measured on-device before the next:

1. `3929c0d` — `ContactManager.mlkemEligibleContacts()`/`globalTrusteeIdentifiers()` changed to derive the local-DB key once internally per call instead of once per contact per field. **11s → 2.15s.**
2. `e97a542` — vault key (`distributionMeta`) and the `mlkemContacts`/`selected`/`k`/`canMark` chain hoisted to local `let`s computed once in `body`, threaded down as parameters instead of re-read from computed properties at every call site. **2.15s → ~1.1s** (folded into the next commit's measurement).
3. `0686126` — `globalTrusteeIDs` (the "GLOBAL" badge check), the one remaining per-row read, given the same treatment. **→ 1.02s, final measured number.**

The design that shipped is **not** the one originally scoped below (a `@State`-cached result with `.onChange` invalidation) — that approach was reconsidered mid-investigation in favor of something with no caching and no invalidation logic anywhere; see "What actually shipped" for the real design and why it changed. The original root-cause tracing below is kept as-is — it's still an accurate account of the bug — but the "Scoped fix" section is superseded.

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

## Scoped fix (vault key only — local-DB key below is a separate, unscoped problem) — superseded, kept for the reasoning trail

**Not what shipped.** This section was written before the local-DB-key side was scoped, and proposes a `@State`-cached `distributionMeta` with `.onChange(of: vaultEntries)`/`.onChange(of: bekRows)` reactivity plus explicit post-mutation refresh calls. That design was reconsidered during review — see "What actually shipped" below for what was built instead and why. Kept here for the reasoning trail, not as the implemented design.

Lower-risk than the sibling bug's fix, because the expensive part (the `SymmetricKey` itself) never needs to leave `VaultManager` or be threaded through the View at all. What's actually worth caching at the View layer is `distributionMeta`'s *decrypted result* — `ShardDistributionMetadata`, plain bookkeeping data (contact IDs, shard status, threshold) this screen exists to display, not key material. So unlike the sibling fix, there's no `SymmetricKey`-lifetime reasoning to work through here; the key still only lives for the duration of one `deriveVaultKey` + `AES.GCM.open` call, exactly as today — the only change is calling that pair far less often.

**Shape of the change:**
- Replace the computed `distributionMeta` property with a `@State private var distributionMeta: ShardDistributionMetadata?`, populated by a new `refreshDistributionMeta()` method instead of recomputed on every read.
- Call `refreshDistributionMeta()` once in `seedInitialState()` (already wired to `.onAppear`).
- Add `.onChange(of: self.vaultEntries)` / `.onChange(of: self.bekRows)` on the view, each calling `refreshDistributionMeta()` — this is what preserves the *existing, intentional* reactivity documented on the current computed property ("re-renders whenever VaultEntry or BackupEncryptionKey changes in the persistent store, e.g. when `processInboundManifest` confirms a shard"). Losing this would be a real regression, not just a missed optimization, if the naive fix were "populate once in `onAppear` and never again."
- All existing read sites (`hasExistingDistribution`, `shardRecord(for:)`, the two direct reads in `markForDistribution`) stay textually unchanged — they'd just be reading a cheap stored property instead of triggering a derivation.

**One correctness subtlety, not just a perf one:** two call sites read `distributionMeta` *immediately after a local mutation* that changes the underlying encrypted field — `markForDistribution()` right after `performPrepareShards()`, and `revokeShard()` right after `updateShardStatus()`. `@Query`'s own propagation isn't guaranteed to have landed synchronously by that point, so relying solely on `.onChange(of: vaultEntries)` for those two spots risks reading stale cached data on the very next line. Both need an explicit `refreshDistributionMeta()` call right after their mutation, not just reliance on the `@Query` watcher.

**Why not cache the `SymmetricKey` itself instead:** would require exposing raw key material to the View layer, which the current architecture deliberately doesn't do — `VaultManager` derives and consumes the key internally, in one call. Caching the already-decrypted application data is both simpler and keeps that boundary intact.

## What actually shipped

Two independent design changes, one per key, layered together. Neither uses `@State` caching or any invalidation logic — the guiding principle that emerged during review was **"no caching anywhere, derive/fetch once per need, thread the result down as a parameter"**, not "cache the result and remember to invalidate it."

### Local-DB key — moved into `ContactManager`, still no caching

Rather than the View managing a key at all (an earlier, discarded direction considered and rejected — a `SymmetricKey` sitting in `@State` was judged too broad and uncontrolled a surface, and a `ContactManager`-internal cached key raised a real invalidation risk once it was confirmed the local-DB key genuinely rotates during Secure Mode activation via a staged-key commit protocol), `ContactManager.mlkemEligibleContacts()` and `globalTrusteeIdentifiers()` were changed to derive the key once **per call**, internally, and immediately discard it:

```swift
func mlkemEligibleContacts() -> [Contact.Profile] {
    guard let key = try? Manager.Key().createHybridLocalEncryptionKey() else { return [] }
    return self.mlkemEligibleContacts(usingKey: key)
}
```

This alone collapsed the local-DB-key cost from "once per contact per field" (the ~550-derivation worst case estimated in "A second, likely larger cost" above) down to "once per *call* to these methods" — still redundant if called many times per render, but each call now costs one derivation instead of scaling with address-book size. Measured: **11s → 2.15s.**

A side effect worth noting: getting here required deciding where the keyed decrypt logic should live at all. It was **not** added to `Manager.Security` (which previously owned the unkeyed `isVisible`/`isDisplayable` too) — that coupling of the security-state manager to `Contact.Profile`'s field layout was reconsidered and removed entirely. The comparison logic moved to `Contact.Profile` itself as `isVisible(atDepth:)` / `isVisible(atDepth:usingKey:)` / `isGlobalTrustee(atDepth:usingKey:)`, mirroring how `Group` already owns its own depth/key-aware query methods. `Manager.Security` now has zero methods that take a `Contact.Profile` — see `a0c1323`, which also updated all 14 pre-existing call sites across the app to the new shape with no behavior change.

### Vault key + remaining call-frequency redundancy — hoisted to `body`, threaded as parameters

`VaultManager.shardDistributionMetadata(for:)` already derived its key once per call — that was never the problem. The problem was `distributionMeta` (and, on the local-DB side, `mlkemContacts`/`selected`/`k`/`canMark`/`globalTrusteeIDs`) being **computed properties re-read many times per render** from `ctaBar`'s repeated ternaries and the trustee-row loop.

`body` now computes everything once:
```swift
var body: some View {
    let meta       = self.fetchDistributionMeta()
    let contacts   = self.mlkemContacts
    let trusteeIDs = self.globalTrusteeIDs
    let selected   = contacts.filter { self.selectedIDs.contains($0.identifier) }
    let k          = max(2, min(self.threshold, max(2, selected.count)))
    let canMark    = selected.count >= 2
    // ...threaded down as parameters to summaryCard, trusteesHeader, trusteesCard,
    // trusteeRow, infoNote, contextNote, ctaBar, avatarStack
}
```

`distributionMeta`, `selected`, `k`, `canMark`, `ctaTitle`, `ctaEnabled`, and `hasExistingDistribution` no longer exist as properties — `fetchDistributionMeta()` replaces `distributionMeta`, called once in `body` and independently in the two action methods (`seedInitialState`, `markForDistribution`), which run outside `body`'s render pass and always need their own fresh read regardless. The CTA button was also pulled out into its own `DistributionCTAButton` view taking `title`/`enabled`/`isMarking`/`canMark`/`action` as plain stored properties, instead of reaching into six different properties on the parent.

This is deliberately **not** a persistent-cache design — there's nothing to go stale, because everything is recomputed fresh from current `@Query`/`@State` on every `body` evaluation. The reactivity `distributionMeta` originally needed (picking up a background shard confirmation via `processInboundManifest` while the screen is open) falls out automatically: `@Query` changes still trigger a `body` re-evaluation, which recomputes `meta` fresh, no `.onChange` scaffolding required. Measured after both this and the local-DB-key fix together: **→ 1.02s.**

## Residual, not chased further

- **Per-derivation wall-clock baseline was never isolated.** The three measurements above (11s → 2.15s → 1.02s) are real, on-device, end-to-end numbers, not derived from a controlled per-call timing baseline — useful for confirming the fixes worked, not for predicting behavior at a different contact count.
- **`body` may still evaluate more than once per visible render** (state settling, layout passes) — the fixes reduce every known redundant call site to "once per `body` evaluation," which is the limit of this approach; going lower would mean either accepting SwiftUI's own re-render frequency as fixed cost or moving the derivation off the render path entirely (the "background thread" direction considered and set aside earlier in this investigation, since `createHybridLocalEncryptionKey`/`deriveVaultKey` default to `MainActor` project-wide and were never marked `nonisolated`).
- **1.02s may still be worth chasing further** if it's judged not good enough — this doc doesn't take a position on that, it just records what was fixed and measured.

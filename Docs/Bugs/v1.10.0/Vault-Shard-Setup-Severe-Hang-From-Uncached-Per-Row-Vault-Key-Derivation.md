# Opening a vault entry's "Manage Shards" screen causes a severe hang — vault key re-derived from scratch per trustee row

**Status:** open, not fixed. Found via an Instruments trace showing an 11-second hang when opening `VaultShardSetup` from a vault entry's detail view, with only 3 eligible ML-KEM contacts — disproportionate to contact count, which pointed at a fixed cost beyond the trustee-row loop (see "The multiplier" below). Root cause identified by code reading, not yet independently re-profiled on-device with a controlled contact count — see "Not yet done" at the bottom. Same anti-pattern as the already-fixed `Group-Reencryption-Multi-Second-Block-On-Visibility-Toggle.md` (uncached SE/Keychain key derivation, paid many times over per screen instead of once), independently reintroduced here in a different code path that fix never touched.

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

## Why this wasn't caught by the sibling bug's fix

The visibility-toggle fix (`Group-Reencryption-Multi-Second-Block-On-Visibility-Toggle.md`) scoped its change to `Data.encrypt()`/`Data.decrypt()`'s local-DB key path (`createHybridLocalEncryptionKey()`), which is a separate SE key entirely from the vault key (`deriveVaultKey`) used here. The two paths share the same *shape* of bug — an expensive, uncached per-call SE/Keychain derivation invoked once per list item — but are different code, so fixing one didn't touch the other. No general "derive once, cache for the duration of a screen" convention exists in this codebase to prevent a third instance of the same pattern elsewhere.

## Not yet done

- **Per-derivation wall-clock cost.** 11 seconds ÷ 8 known derivations (5 CTA bar + 3 rows) ≈ 1.4s each if `body` evaluated exactly once — plausible for Keychain/SE IPC under Instruments' own tracing overhead, but `body` almost certainly evaluated more than once here, so the true per-derivation cost is unmeasured. Worth an isolated trace of a single `deriveVaultKey` call to get a real baseline, then correlating against a counted number of `body` evaluations for this screen specifically.
- **No fix proposed or implemented.** The likely direction mirrors the sibling bug's shipped fix — derive the vault key once per screen appearance (e.g. in `seedInitialState()` or a `@State`-cached value) and thread it through instead of letting `distributionMeta` re-derive it on every read — but that's scoping, not something landed here.

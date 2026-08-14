# Secure Mode — Key Rotation Contract & Change Checklist

Every Secure Mode code change **must** pass through this checklist before merge.
The checklist exists because key rotation has a narrow critical section between
"staged key committed" and "old key deleted" where a single missing save can make
all contacts permanently unreadable. Bugs 34–37 were all in this area.

---

## Core Invariants

These must hold **at all times** between any two successful app launches:

| # | Invariant |
|---|-----------|
| I1 | Every non-nil field on every `Contact.Profile` row in SQLite is ciphertext encrypted under the **current canonical local DB key**. No row may contain ciphertext from a superseded key. |
| I2 | Every non-nil `visibleThroughDepth` on `Contact.Profile` and `VaultEntry` is also encrypted under the current canonical key. |
| I3 | `contactManager.modelContext` and `vaultManager.modelContext` are **fully flushed to the WAL** before `commitStagedLocalDBKey()` is called. |
| I4 | The WAL checkpoint runs **after** `commitStagedLocalDBKey()`, never before. Checkpointing before commit would move pre-rotation ciphertext into the main file. |
| I5 | The old canonical SE key is deleted **only after** a successful WAL checkpoint. |
| I6 | The app group **always** contains a blob — either a real payload (Secure Mode active) or an indistinguishable no-op. This is true regardless of which `LayerStoreBackend` destination is active. An absent app-group blob is a forensic tell. |
| I7 | `AppLayerConfig` **always** exists from the very first launch. Its presence is not a forensic tell for PIN or Secure Mode usage. Sensitive fields (`sealedNormalVerifier`, `sealedDuressVerifier`) are nil when those features are not configured; the row itself is always there. Never delete the row — reset fields to nil instead. |

| I8 | Every **model** holding a field sealed under the local DB key is re-keyed in **both** `activateSecureMode` and `deactivateSecureMode`. Not one of them. Both. |

---

## Model Coverage

**This section exists because I8 has been broken four times, and every time the same way.**

The rotation stages a new local DB key, re-encrypts, commits, then deletes the superseded key.
Anything not re-encrypted in between is sealed under a key that no longer exists — permanently,
because the hybrid key needs a Secure Enclave half that is non-exportable. There is no repair
pass, on this device or any other.

Every instance failed silently, and that is by design rather than bad luck: `reencryptAllFields`
nils fields it cannot decrypt, read accessors have safe fallbacks, `compactMap` swallows a nil,
`if let` swallows a missing key. The system degrades quietly for forensic reasons. That property
is correct and is exactly what hides this bug class.

| Bug | Model | Missed in |
|-----|-------|-----------|
| 75 | `Group` | both paths |
| 76 | `AppLayerConfig` | both paths |
| 77 | `Contact.Profile.maxBundleVersion`, `.deletionToken` | the field list |
| — (2026-08-14) | `Message.Draft` | **deactivation only** — activation had it from the start |

The last one is the important lesson and the reason this section is not just a longer field
list. The checklist below used to ask *"does this change add an encrypted field to
`Contact.Profile`?"* — a field-level question about one model. Nobody was asked the model-level
question, so `Group` and `AppLayerConfig` went unnoticed for as long as they existed. And when
those two were finally added to both paths, `Message.Draft` — which had been correct in
activation since the beginning — was not checked against deactivation, because nobody was
asked *"is every model in **both** paths?"* either.

### Sealed under the rotating local DB key — must be in both paths

| Model | What is sealed | Re-keyed by | Enforcement |
|---|---|---|---|
| `Contact.Profile` + `PhoneNumber` / `EmailAddress` / `PostalAddress` / `URLAddress` | every text field, images, `visibleThroughDepth`, `globalTrusteeDepth`, `originDepth`, `signedAttributes`, `forwardSecrecyEncrypted`, `maxBundleVersion`, `deletionToken` | `reencryptAllFields(to:aad:)` | `EncryptedFieldCoverageTests` name tripwire + behavioural rotation test |
| `Contact.Profile.Key` | `material`, `acquiredAt`, `owner`, `expiredOn`, `quantumKeyMaterialEncrypted` | `reencryptKeyRecords` | `EncryptedFieldCoverageTests` |
| `Group` | `encryptedID`, `encryptedName`, `encryptedCreatedAt`, all 32 depths of membership | `Group.reencrypt(from:to:)` | `EncryptedFieldCoverageTests` + `GroupKeyRotationTests` |
| `AppLayerConfig` | `persistedDepth`, `pinEnabled`, `coercerBaseDepth`, `lockoutCountEncrypted`, `lockoutAnchorUptimeEncrypted`, `pinEnabledPerDepth` | `AppLayerConfig.reencrypt(from:to:)` | `EncryptedFieldCoverageTests` + `AppLayerConfigRotationTests` |
| `Message.Draft` | `encryptedRecipientID`, `encryptedContent` | `Message.Draft.reKeyOrPurgeAll` | `DraftKeyRotationTests` — **no name tripwire**, see below |
| `VaultEntry` | `visibleThroughDepth` only | inline loop in both paths | `SecureModeActivationTests` |

### Sealed under a key that never rotates — must **not** be added to the rotation

Putting one of these through the rotation is as much a bug as leaving one of the above out: it
would re-seal under the wrong key and strand the field the other way round.

| Model / field | Key | Why it is not the local DB key |
|---|---|---|
| `AppLayerConfig.sealedNormalVerifiers`, `.sealedDuressVerifier` | SE Secure Mode key, via `PINManager` | Why PIN entry kept working across rotations even while everything else on the row did not |
| `AppLayerConfig.sealedBlobSlots`, `.layerSequenceNumbers` | `AppLayerConfig.blobMetadataKey(from:)`, HKDF from the SE Secure Mode key | Moved there by Bug 76's fix, so no rotation can strand them *by construction* rather than by remembering |
| Layer store payload | `LayerStore.deriveKey(from:)`, SE Secure Mode key | Must survive the rotation it is taken across |
| `CustodyShard`, `PendingShardDistribute`, `PendingShardStatusUpdate`, `GlobalShardConfig` | `deriveShardCustodyKey` (SE, `.privateKeyUsage`) | Automatic shard operations run without user approval |
| `BackupEncryptionKey`, `VaultEntry` label / value | vault key (SE, biometry or passcode) | Deliberately gated on user presence |
| `ReconstructShard.encryptedPayload` | return-buffer key | Scoped to a reconstruction session |
| Prekey private keys | SE, per-contact tags | Never leave the Enclave; deleted by `consume`, not re-keyed |

`Contact.Message` is registered in the schema but has no local encryption helpers — its `content`
is already ciphertext from the bundle path. Verify before assuming, if it is ever used.

### Adding a new encrypted field

1. Decide which key seals it, using the two tables above. If it is anything other than the local
   DB key, add it to the second table and stop.
2. Add it to that model's re-key function.
3. Add its name to the model's list in `EncryptedFieldCoverageTests`, if the model has one. The
   tripwire fails the build on any stored property it has not been told about, which is what
   forces this decision to be made rather than skipped.
4. Decide whether it must survive activation. If so it also needs to be in `LayerContact`, its
   encoder/decoder, and deactivation's Step 5 restore loop.
5. Write a behavioural test: populate it, rotate, assert it still reads.

### Adding a new model

1. Everything above, plus:
2. **Add it to both paths.** Activation's Step 8 and deactivation's Step 6b. A model in one path
   only is the `Message.Draft` bug.
3. Add it to `EncryptedFieldCoverageTests` so a future field on it cannot be missed. `Message.Draft`
   is currently absent from that file — it is covered by behavioural tests only, which catch a
   missing *call* but not a missing *field*.
4. Mind the ordering. Anything that resolves an identifier through a decrypt of another model
   must run before that model is re-keyed. Drafts are re-keyed before groups in both paths for
   exactly this reason: `Group.readID()` decrypts with the *canonical* key, which is still the
   old key until the commit, so re-keying groups first would collapse `allGroupIdentifiers` to
   empty and take `reKeyOrPurgeAll` down its delete branch for every group-addressed draft.
5. Write the test against the **real** `activateSecureMode` / `deactivateSecureMode`, not against
   the re-key helper. The helper is rarely the bug; the missing call is. A unit test of
   `reKeyOrPurgeAll` passed throughout the entire lifetime of the deactivation bug.

### Reviewing a change to either path

Ask the model-level question first, and ask it twice:

- Which models hold something under the rotating key? (the first table)
- Does **each** appear in `activateSecureMode`?
- Does **each** appear in `deactivateSecureMode`?

The two functions are separate code paths that happen to do the same thing. A fix applied to one
is not applied to the other, and nothing in the type system will say so.

---

## Key Rotation Sequence (canonical order — do not reorder)

```
1.  [Activation only] Classify contacts → build blobContacts / safeProfiles
2.  createStagedLocalDBKey()                      ← staged key now exists in Keychain
3.  [Activation only] Seal blob
4.  reencryptAllFields / reencryptKeyRecords       ← mutate model objects in contactManager.modelContext
5.  contactManager.modelContext.save()             ← FLUSH to WAL  ← INVARIANT I3
6.  [Activation only] Re-encrypt VaultEntry depth fields
    vaultManager.modelContext.save()               ← FLUSH to WAL  ← INVARIANT I3
7.  [Deactivation only] Restore blob contacts via contactManager.save(contact:using:)
    [Deactivation only] Set visibleThroughDepth / signedAttributes on security context
    [Deactivation only] self.modelContext.save()   ← flush blob contact depth/attrs
8.  [Deactivation only] Clear VaultEntry depth fields
    vaultManager.modelContext.save()               ← FLUSH to WAL
9.  commitStagedLocalDBKey()                       ← POINT OF NO RETURN
10. walCheckpoint(at:)                             ← only safe AFTER commit (I4)
11. deleteSupersededLocalDBArtefacts()             ← only safe AFTER checkpoint (I5)
12. [Activation] self.modelContext.save()          ← persist duress verifier
    [Deactivation] config.sealedDuressVerifier = nil; self.modelContext.save()
13. [Deactivation] rewriteLayerStore()
```

**Rule**: any new save added to the sequence must appear at or before step 9.
Any save added after step 9 that touches Contact.Profile or VaultEntry fields
writes new-key ciphertext — correct, but pointless. It cannot fix data written
before step 9 without a full re-encryption pass.

---

## The "missing save" failure mode (Bugs 36 / 37 regression)

Calling `reencryptAllFields` mutates **in-memory** SwiftData objects only.
Without an explicit `modelContext.save()` before `commitStagedLocalDBKey()`:

1. WAL checkpoint (step 10) flushes an empty or irrelevant WAL.
2. The main SQLite file still contains pre-rotation ciphertext.
3. The old SE key is deleted (step 11).
4. Autosave or a context merge notification may restore the in-memory objects
   from disk, replacing staged-key ciphertext with the now-unreadable old-key
   ciphertext.
5. Result: every `data.decrypt()` returns `nil` → `isVisible` returns `false`
   for every contact → contacts invisible in both normal and duress mode.
6. On subsequent deactivation: `reencryptAllFields` cannot decrypt the garbled
   fields → leaves original ciphertext in place → after the new key rotation,
   all text fields are permanently unreadable ("corrupted fields").

---

## Change Checklist

### Modifying `activateSecureMode`

- [ ] Does the change add or rename an encrypted field on `Contact.Profile`?
      → Update `reencryptAllFields` in `Contact+Model+Reencrypt.swift`.
- [ ] Does the change add or rename a key-record field on `Contact.Profile.Key`?
      → Update `reencryptKeyRecords`.
- [ ] Does the change add a new save or model mutation?
      → Verify the save occurs **before** step 9 (`commitStagedLocalDBKey`).
- [ ] Does the change move or remove `contactManager.modelContext.save()`?
      → Stop. Confirm I3 is preserved by another explicit flush.
- [ ] Does the change affect `LayerContact` or `LayerPayload`?
      → Update both `seal()` in activation and the restore loop in deactivation.
- [ ] Does the change modify `visibleThroughDepth` classification?
      → Verify `isVisible` at depth 0 (normal) and depth .max return correct results.
- [ ] Does the change add, rename, or remove a **model** sealed under the local DB key?
      → Walk the Model Coverage tables above. Whatever you do here must also be done in
         `deactivateSecureMode` — see I8.
- [ ] Does the change reorder Step 8's passes?
      → Drafts must be re-keyed before groups. `Group.readID()` uses the canonical key.
- [ ] Run `StagedKeyTests`, `SecureModeActivationTests`, `GroupKeyRotationTests`,
      `AppLayerConfigRotationTests`, `DraftKeyRotationTests`, `EncryptedFieldCoverageTests`.

### Modifying `deactivateSecureMode`

- [ ] Does the change add an encrypted field to `Contact.Profile`?
      → Update `reencryptAllFields`. Verify the field is also in the blob restore
         loop if it must survive across activation/deactivation cycles.
- [ ] Does the change move or remove `contactManager.modelContext.save()` (Step 5)?
      → Confirm I3 is preserved. Note: when `payload.contacts` is empty, Step 7's
         `contactManager.save(contact:using:)` does not run — the explicit save
         after Step 4 is the only flush for safe contacts in that path.
- [ ] Does the change reorder the final `self.modelContext.save()` relative to
      `commitStagedLocalDBKey()`?
      → The config save must come **after** step 9. Moving it before is invalid.
- [ ] Does Step 6b still re-key **every** model in the first Model Coverage table?
      → Drafts, groups, config. This checklist previously asked only about `Contact.Profile`,
         which is how `Message.Draft` stayed missing here while being correct in activation.
- [ ] Does the change reorder Step 6b's passes?
      → Drafts before groups, same reason as activation.
- [ ] Run `StagedKeyTests`, `GroupKeyRotationTests`, `AppLayerConfigRotationTests`,
      `DraftKeyRotationTests`.

### Adding a new encrypted field to `Contact.Profile`

- [ ] Add the field to `reencryptAllFields` in `Contact+Model+Reencrypt.swift`.
- [ ] If the field is a `Data` blob (not a base64 string), use the `reencrypt(data:)` overload.
- [ ] If the field must survive activation (i.e., must be restored on deactivation),
      add it to `LayerContact`, update `LayerContact` encoder/decoder,
      and update the blob restore loop in `deactivateSecureMode` Step 5.
- [ ] Update the deactivation Step 4 if the field needs to be cleared (like `visibleThroughDepth`).
- [ ] Write a unit test in `StagedKeyTests` that verifies the field round-trips
      through activation → deactivation with correct values.

### Modifying `isVisible` or contact depth filtering

- [ ] `nil` visibleThroughDepth → visible (pre-activation default, must stay true).
- [ ] `Int.max` → visible at every depth.
- [ ] `0` → visible only at depth 0 (normal), hidden at depth ≥ 1 (duress).
- [ ] Non-decryptable ciphertext → hidden (conservative; never show unreadable data).
- [ ] Verify `safeContactIDs(atDepth:)` produces the correct set at depth 0 and 1.

### Modifying the lock / unlock flow (`handleActive`, `handleBackground`, `unlockNormal`, etc.)

- [ ] `isContentHidden` and `needsPINEntry` must always change **together**.
      A cover without a PIN gate, or a PIN gate without a cover, creates a
      visible state machine inconsistency.
- [ ] `unlockNormal()` / `unlockDuress()` must be called inside the same
      synchronous block as `applyVerifyState(for:)` so SwiftUI batches both
      mutations into one render pass (prevents flash of wrong-depth content).
- [ ] Grace period logic: `isWithinGracePeriod` reads `lastUnlockDate`. Any path
      that skips PIN re-entry without calling `recordUnlock()` must explicitly
      verify it is within the grace period first.
- [ ] In restricted (duress) mode the grace period is always zero. Any shortcut
      that auto-unlocks must guard on `!isRestricted`.

### Modifying blob maintenance (`maintain`, `rewriteLayerStore`)

- [ ] Never call `rewriteLayerStore` when `sealedDuressVerifier != nil`.
      The blob holds a real payload; overwriting it destroys deactivation data.
- [ ] `rewriteLayerStore` is debounced (30 s) and gated on `!security.isSecureModeActive`
      in `OccultaApp`. Maintain both guards if the call site changes.
- [ ] App group no-op maintenance must run regardless of which `LayerStoreBackend` destination
      is active. If a future destination stores the real payload externally, the app group
      still needs its no-op blob — see I6 and the LayerStoreBackend section below.

### Modifying `AppLayerConfig`

- [ ] Never `modelContext.delete(config)`. Reset sensitive fields to nil instead.
      See I7. The row must outlive any particular feature state.
- [ ] New fields that encode a user preference or security state must always be
      written on first launch (bootstrap in `Security.init()`). A field that only
      appears when a feature is active is itself a forensic tell.
- [ ] The bootstrap seed must encode the same safe default a user who never touched
      the feature would expect: nil verifiers, `.normal` depth, `pinEnabled = true`,
      `blobStoreDestination = .appGroup` (once added).

---

## Layer Store Protocol (Implemented)

`LayerStoreBackend` protocol decouples layer store I/O from crypto. `Manager.LayerStore` owns
all cryptography; backends handle only raw ciphertext bytes.

```swift
/// Layer store I/O back-end. Manager.LayerStore owns all crypto (padding, AES-GCM, HKDF).
protocol LayerStoreBackend {
    func write(_ encryptedData: Data) throws
    func read() throws -> Data   // throws Manager.LayerStore.Error.notFound if absent
    func delete()
    var exists: Bool { get }
}
```

- `LayerStoreBackend` protocol and `AppGroupLayerStoreBackend` in `SecureMode+LayerStoreBackend.swift`. ✅
- `seal/unseal` take `store: any LayerStoreBackend`. ✅
- `Manager.Security` holds `private let blobStore: any LayerStoreBackend` (default `AppGroupLayerStoreBackend()`). ✅
- Tests use `InMemoryLayerStoreBackend` (`OccultaTests/SecureMode/InMemoryLayerStoreBackend.swift`). ✅
- No-op maintenance (`maintain`, `rewriteLayerStore`) targets `AppGroupLayerStoreBackend` — I6. ✅

## Alternative Destinations (Future)

**New `AppLayerConfig` field**

```swift
// Encrypted enum — which store holds the real payload.
// Always written during bootstrap so its presence is not a tell.
var blobStoreDestinationEncrypted: Data?   // default: .appGroup
```

The field is encrypted (same local DB key) so a raw DB examiner cannot read the
destination without the canonical key. It is set during bootstrap (`.appGroup`) so
it exists on every install from day one.

**Destination enum**

```swift
enum LayerStoreBackendDestination: Codable {
    case appGroup                          // default, always available
    case externalDocument(bookmark: Data)  // security-scoped bookmark, iOS Files / flash drive
    // future cases here
}
```

The `bookmark` is a security-scoped bookmark created from the URL returned by
`UIDocumentPickerViewController`. It is stored encrypted inside the enum's associated
value — a single encrypted blob that contains both the destination tag and the
bookmark data.

**What future destinations must honour**

| Concern | Requirement |
|---|---|
| No-op in app group | App group always has a no-op blob regardless of destination (I6). |
| Availability at deactivation | If the external store is unavailable, deactivation falls back to `LayerPayload(contacts: [])` and continues — same as today's `notFound` path. User loses sensitive contacts; that is a documented tradeoff. |
| Crash / orphan | If activation seals to an external store and then crashes before the key commits, the orphaned blob on the external store is encrypted (harmless). The next successful activation overwrites it via `store.write()`. |
| No metadata trail | External destinations must not write any local file that records which destination was chosen, beyond the encrypted `AppLayerConfig` field. The picker UI should be presented at a point in the flow that does not correlate with the activation timestamp. |
| Destination change | The destination stored in `AppLayerConfig` is fixed for the lifetime of one activation. Changing the destination takes effect only on the next activation cycle (deactivate → change → activate). Mid-cycle destination migration is not supported. |

**When to present the destination picker**

The picker (if any) is presented in Settings, separately from the activation
flow, before the user starts activation. The chosen destination is stored in
`AppLayerConfig` before activation begins. The activation sequence reads
`config.blobStoreDestination` at the start and uses that store throughout.

Every activation/deactivation bug to date was caught only at runtime, not by tests.
For any change in this area:

1. **Unit test**: `StagedKeyTests` — exercises the key rotation path in isolation.
2. **Integration test**: Activate → enter both PINs → verify contacts visible at
   each depth → Deactivate → verify all contacts visible with correct plaintext.
3. **Restart test**: After activation, kill and relaunch the app. Contacts must
   still be readable. This catches the "dirty-but-unsaved" failure mode.
4. **Empty-blob path**: Deactivate when there are zero sensitive contacts (blob is
   a no-op payload). Safe contacts must be readable after deactivation.

---

_Last updated: 2026-06-01. Update this document whenever the rotation sequence or LayerStoreBackend design changes._

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
| I6 | The app group **always** contains a blob — either a real payload (Secure Mode active) or an indistinguishable no-op. This is true regardless of which `BlobStore` destination is active. An absent app-group blob is a forensic tell. |
| I7 | `AppLayerConfig` **always** exists from the very first launch. Its presence is not a forensic tell for PIN or Secure Mode usage. Sensitive fields (`sealedNormalVerifier`, `sealedDuressVerifier`) are nil when those features are not configured; the row itself is always there. Never delete the row — reset fields to nil instead. |

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
13. [Deactivation] rewriteNoOpBlob()
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
- [ ] Does the change affect `ContactBlobRecord` or `BlobPayload`?
      → Update both `seal()` in activation and the restore loop in deactivation.
- [ ] Does the change modify `visibleThroughDepth` classification?
      → Verify `isVisible` at depth 0 (normal) and depth .max return correct results.
- [ ] Run `StagedKeyTests` and `SecureModeActivationTests`.

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
- [ ] Run `StagedKeyTests`.

### Adding a new encrypted field to `Contact.Profile`

- [ ] Add the field to `reencryptAllFields` in `Contact+Model+Reencrypt.swift`.
- [ ] If the field is a `Data` blob (not a base64 string), use the `reencrypt(data:)` overload.
- [ ] If the field must survive activation (i.e., must be restored on deactivation),
      add it to `ContactBlobRecord`, update `ContactBlobRecord` encoder/decoder,
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

### Modifying blob maintenance (`maintainNoOpBlob`, `rewriteNoOpBlob`)

- [ ] Never call `rewriteNoOpBlob` when `sealedDuressVerifier != nil`.
      The blob holds a real payload; overwriting it destroys deactivation data.
- [ ] `rewriteNoOpBlob` is debounced (30 s) and gated on `!security.isSecureModeActive`
      in `OccultaApp`. Maintain both guards if the call site changes.
- [ ] App group no-op maintenance must run regardless of which `BlobStore` destination
      is active. If a future destination stores the real payload externally, the app group
      still needs its no-op blob — see I6 and the BlobStore section below.

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

## BlobStore Refactor (Planned)

### Motivation

`Manager.Blob.seal/unseal` currently take a `directory: URL?` which is nil in
production (hard-coded app group path) and a temp URL in tests. Adding alternative
destinations (external storage, etc.) by extending this parameter is not scalable.
The refactor decouples blob I/O from blob crypto behind a protocol.

### Protocol contract (I/O only — no crypto)

```swift
/// Blob I/O back-end. Manager.Blob owns all crypto (padding, AES-GCM, HKDF).
/// Implementations handle only reading and writing raw ciphertext bytes.
protocol BlobStore {
    /// Write already-encrypted, already-padded ciphertext, replacing any
    /// existing blob. Throws on I/O failure (permissions, device full, etc.).
    func write(_ encryptedData: Data) throws

    /// Return raw ciphertext. Throws `BlobError.noBlobFound` if absent,
    /// `BlobError.decryptionFailed` if data is present but unreadable.
    func read() throws -> Data

    /// Delete the current blob. No-op if absent.
    func delete()

    /// True if a blob file exists at this location (content not checked).
    var hasBlob: Bool { get }
}
```

`Manager.Blob.seal(_:blobKey:store:)` and `unseal(blobKey:store:)` accept a
`BlobStore` instead of `directory: URL?`. The call sites in `activateSecureMode`
and `deactivateSecureMode` pass the store from a `Security` property (injectable,
like `keyManager` and `blobDirectory` already are).

No-op maintenance (`maintainNoOpBlob`, `rewriteNoOpBlob`) always targets the
`AppGroupBlobStore` regardless of which store holds the real payload — I6.

### Phase 1 — protocol shell, app group only (current scope)

- Introduce `BlobStore` protocol and `AppGroupBlobStore` (wraps current logic).
- Remove `directory: URL?` from `seal/unseal`; replace with `store: any BlobStore`.
- `Manager.Security` gets `private let blobStore: any BlobStore` replacing `blobDirectory: URL?`.
- Tests switch from `blobDirectory: tempURL` to an `InMemoryBlobStore` — eliminates
  temp-directory collisions and the `URL?` hack.
- No user-facing behaviour change. No new `AppLayerConfig` field yet.

### Phase 2 — additional destinations (future)

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
enum BlobStoreDestination: Codable {
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
| Availability at deactivation | If the external store is unavailable, deactivation falls back to `BlobPayload(contacts: [])` and continues — same as today's `noBlobFound` path. User loses sensitive contacts; that is a documented tradeoff. |
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

_Last updated: 2026-06-01. Update this document whenever the rotation sequence or BlobStore design changes._

# Marking a contact private/safe blocks the main thread for several seconds

**Status:** key-derivation fix implemented (see "Implementation status" at the bottom). UX mitigation from the original pass (loading state + re-tap guard on the toggle, `Occulta/UI/Tabs/Contacts/v2/TrustCheckV2.swift`, `HideDestinationV2`) is still in place underneath it. Found while wiring the Trust Check "Hide/Mark safe" toggle to reach an already-hidden contact for the first time (previously the option disappeared once a contact was hidden, so this path was never exercised from the UI). Root cause below was corrected after profiling (see "Profiling correction"); the fix that followed from it is implemented (see "Scoped fix" and "Implementation status").

## Symptom

Toggling a contact's visibility (`ContactManager.setVisibility(for:isSensitive:)`, `Occulta/Services/ContactManager+Classification.swift:77`) freezes the UI for 5+ seconds on device, with no loading indicator, no ability to cancel, and a second tap during the freeze queues a second full pass on top of the first.

## Root cause: two compounding, pre-existing behaviors

Neither of these is new — the old `Contact.FormV2` "Private contact" toggle called the exact same `setVisibility`, so this cost already existed before Trust Check. It just wasn't obvious because the deleted-form toggle was one-directional in practice and rarely exercised repeatedly in a single session.

### 1. `setVisibility` re-encrypts every group in the database, not just ones the contact belongs to

`setVisibility` → `cleanUpGroupDuressMembership(hiddenIdentifiers:)` (`ContactManager+Classification.swift:124`) → `forEachGroup` (`Contact+Manager+Groups.swift:102`), which fetches and touches **every** `Group` row unconditionally:

```swift
func forEachGroup(_ operation: (Group) throws -> Void) throws {
    for group in try self.modelContext.fetch(FetchDescriptor<Group>()) {
        try operation(group)
    }
    try self.modelContext.save()
}
```

For each group, `Group.refreshCiphertext()` (`Data Models/Group+Model.swift:204`) re-encrypts **every depth × every slot** — `depthCount = 32`, `slotCount = 32` (`Group+Model.swift:57,74`) — regardless of whether the toggled contact is a member of that group at all. This is deliberate: the doc comment on `cleanUpGroupDuressMembership` explains a database diff must show every group's ciphertext changing on every classification save, so an examiner can't correlate which group or depth was actually touched. The camouflage is intentional and should not be removed — but its cost scales with total groups × total real members across all 32 depths, paid in full on every single toggle.

### 2. `Data.encrypt()`/`Data.decrypt()` never cache the derived key — every call re-derives it from Secure Enclave + Keychain from scratch

Each real member's slot in `Group.encryptedSlots(for:)` (`Group+Model.swift:301`) calls `Data.encrypt()` (`Services/Crypto+Manager.swift:195`), which constructs a fresh `Manager.Crypto()` → `Manager.Key()` and calls `createHybridLocalEncryptionKey()` (`Services/Key+Manager.swift:432`). That function performs, **per call, with no caching across calls**:

- Two `SecItemCopyMatching` Keychain lookups for the local-DB SE private key (`retrieveLocalDBPrivateKey()`, called both directly at `Key+Manager.swift:444` and again inside `deriveLocalDBSEComponent()` at `Key+Manager.swift:536` — the same key is fetched twice per `encrypt()` call).
- One Secure Enclave ECDH exchange (`SecKeyCopyKeyExchangeResult`, `Key+Manager.swift:541`).
- One Keychain lookup for the random component (`retrieveOrCreateRandomComponent()`, `Key+Manager.swift:558`).
- One HKDF derivation.

No biometric gate is involved (the local-DB SE key is device-unlock level, not `.biometryCurrentSet`), so this isn't a Face ID prompt — it's pure Keychain/SE round-trip latency, paid fresh on every single slot, every single call.

### Combined cost

A toggle with, for example, 3 groups and 2 real members per depth does roughly `3 groups × 32 depths × 2 members` ≈ 192 individual `encrypt()` calls, each doing 3 Keychain lookups + 1 SE ECDH exchange, synchronously on the main thread, inside a `Toggle.onChange` closure with no `Task` wrapping at the time this was found. On a real device this plausibly accounts for the full 5+ second freeze.

## Profiling correction: the dominant cost is read-side `decrypt()`, not write-side `encrypt()`

The estimate above (~192 `encrypt()` calls for a 3-group/2-real-member case) turned out to understate the actual cost, and misattributed which side of the crypto path dominates. Instruments Time Profiler on a real device, toggling a contact's visibility with 3 groups (only one holding 2 real members, no duress-depth decoy content built on any of them, Secure Mode never activated), showed a **27-second severe hang**, of which 2.54s was captured as on-CPU sample time. The heaviest stack:

```
ContactManager.setVisibility(for:isSensitive:)
  ContactManager.cleanUpGroupDuressMembership(hiddenIdentifiers:)
    ContactManager.forEachGroup(_:)
      Group.purgeMembersFromDuressDepths(_:)
        Group.reencryptAllDepths(content:)
          Group.members(atDepth:)              ← 1.12s / 44.0%
            Data.decrypt()
              Manager.Crypto.decrypt(data:)
                Manager.Key.createHybridLocalEncryptionKey()   ← 1.11s / 43.8%
                  Manager.Key.deriveLocalDBSEComponent()        — 533ms
                    SecItemResultCopyPrepared (Keychain)        — 315ms
                    TKSEPClientTokenSession / TKSEPKey (SE)     — 143ms + 101ms
                    NSXPCConnection round trip to securityd     — ~90ms
```

**The bottleneck is `Group.members(atDepth:)`, not `encryptedSlots(for:)`.** `members(atDepth:)` (`Group+Model.swift:137-146`) has to attempt `.decrypt()` on *every* slot at a depth to discover which ones are real — filler slots are only identifiable by trying to decrypt them and having it fail; `compactMap` silently drops the failures. That means the expensive key derivation runs on **all 32 slots × all 32 depths × every group**, regardless of how many real members exist. The earlier estimate only counted the write side (`encryptedSlots(for:)`, which does skip derivation for filler slots — those just get cheap `SecRandomCopyBytes`) and missed that `purgeMembersFromDuressDepths`/`reencryptAllDepths` must first *read* current membership via `members(atDepth:)` before it can re-encrypt, and that read pays full cost on every slot. This is why the lag didn't scale down with this test's very sparse membership the way the original math predicted.

**Most of the 27s wasn't CPU time — it was blocked wait time.** The "Severe Hang" region in Instruments spans far longer than the 2.54s of sampled CPU work; the thread was mostly parked in `_dispatch_mach_send_and_wait_for_reply`, waiting on a synchronous XPC round trip to the system security daemon for each Secure Enclave / Keychain operation. `createHybridLocalEncryptionKey()` has no per-call variation — same local-DB SE key, same fixed generator point, same stored random component — so it derives an identical key every time until the local-DB key is rotated, making it fully safe to derive once and reuse for an entire batch rather than re-deriving thousands of times.

**A second call path pays the identical cost, independent of this bug's trigger.** `Group.setMembers(_:atDepth:)` (`Group+Model.swift:260-270`) — the function behind plain `addMember`/`removeMember`, unrelated to visibility toggling — also calls `members(atDepth:)` across all 32 depths before re-encrypting. Same root cause, same 32×32-slot decrypt sweep, triggered by ordinary group-membership edits rather than classification changes.

## Scoped fix: derive the key once, thread it through as a parameter — not a persistent cache

**Status: scoped, not yet implemented.**

Rather than a stored, invalidatable cache (which would need key-rotation invalidation logic and a memory-lifetime policy to reason about), the safer shape is: **derive `createHybridLocalEncryptionKey()`'s result once at the top of the call, pass it down the existing call stack as an ordinary parameter, let it go out of scope when the function returns.** Nothing outlives one synchronous call, so there's no rotation-mid-call risk to design around.

Concretely:
- `ContactManager.cleanUpGroupDuressMembership` derives the key once and captures it in the closure passed to `forEachGroup` — no signature change to `forEachGroup` itself needed.
- `Group` gets key-accepting siblings — `refreshCiphertext(usingKey:)`, `purgeMembersFromDuressDepths(usingKey:)`, and `setMembers` internally — routing through key-accepting versions of `reencryptAllDepths`, `members(atDepth:)`, and `encryptedSlots(for:)`.
- `Manager.Crypto` gets sibling `encrypt(data:using key: SymmetricKey)` / `decrypt(data:using key:)` that skip `createHybridLocalEncryptionKey()` and use the supplied key directly — identical AAD (`EncryptionScheme.v2_hybridPQ.aad`) and per-call fresh nonce, just no re-derivation.
- **`Data.encrypt()`/`Data.decrypt()` — the extensions used at dozens of other call sites app-wide — stay untouched.** Only the group membership read/write path routes through the new key-accepting variants, keeping the security review confined to one call stack rather than the whole crypto layer.

### Security reasoning for the "key as a parameter" design

- `SymmetricKey` is already created and held in memory today for the duration of one `AES.GCM.seal`/`open` call, on every single call — passing it down one synchronous call stack extends an already-accepted exposure, it doesn't introduce a new kind of one.
- No persistence, no instance/singleton storage, no IPC, no disk, no network — a call-stack-local value, deallocated when the outer function returns, same guarantee as today just a longer bound.
- The whole path is synchronous and MainActor-isolated already (`SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor`), so there's no separate thread/actor that could hold a copy longer than expected, and no suspended-task risk from the device locking mid-operation.
- Net exposure plausibly *decreases*: today the key exists transiently ~3,000+ times across 27 seconds of wall clock; proposed, it exists continuously across what should be well under a second.

**Constraints that must hold for that reasoning to stay valid — to enforce during implementation, not assume:**
1. No escaping closures — the key must be passed as an ordinary `let` through ordinary calls only, never captured by a `Task { }` or anything that could outlive the synchronous call.
2. No logging of the key or its raw bytes on the new code paths.
3. Never assigned to an instance property — call-stack-local only.

**Open, unverified:** whether `CryptoKit.SymmetricKey` guarantees zeroing its backing memory on deallocation isn't publicly documented by Apple as a hard guarantee. This isn't a regression introduced by this fix (the existing code already relies on the same assumption for one AES call), but worth flagging as an assumption rather than a certainty if the team wants to verify it directly.

**Also open:** whether to include `setMembers`/`addMember`/`removeMember` in the same pass (same fix, same root cause, different trigger — a scope decision, not a technical blocker) — see "A second call path pays the identical cost" above.

## Why this wasn't caught earlier

The old `ContactFormV2` "Private contact" toggle called the identical `setVisibility` path and would have hit the identical cost — this is not something Trust Check introduced. It's more visible now because Trust Check made the "mark safe again" direction reachable for an already-hidden contact for the first time (the entry used to disappear once `isSensitive` was true, so re-toggling off was never exercised through this UI at all), surfacing a cost path that existed but had gone unexercised.

## What was and wasn't done here

**Done:** `HideDestinationV2`'s toggle now sets `isApplying = true` and disables itself (showing a `ProgressView` instead) for the duration of the call, wrapped in `Task { @MainActor in ... }` so SwiftUI gets a chance to paint that state before the blocking work starts. This does **not** move the work off the main thread — `ContactManager` is not `nonisolated`, and this project defaults to `SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor` project-wide, so the call stays MainActor-isolated regardless of the `Task` wrapper. The UI will still be unresponsive for the same 5+ seconds; the only change is that it now shows a spinner and can't be re-triggered mid-save, instead of looking hung with a silently queueable second pass.

**Not done — deliberately out of scope for this pass:**

1. ~~Deriving the hybrid key once and threading it through as a parameter for a batch of `encrypt()`/`decrypt()` calls.~~ **Implemented** — see "Implementation status" below.
2. **Actually backgrounding `setVisibility` off the main thread.** Would require restructuring `ContactManager`'s SwiftData access (a `ModelContext` is not safely shared across threads/actors as-is) — a larger architectural change, not a toggle-level fix. Still not done — the UI will still be unresponsive for the duration of the (now much shorter) pass, just no longer for 5–27 seconds.
3. **Scoping `forEachGroup` to only groups the toggled contact actually belongs to**, if the camouflage requirement can tolerate that (it currently can't — the doc comment on `cleanUpGroupDuressMembership` is explicit that every group must show a diff on every save, precisely so membership-relevant groups can't be distinguished from irrelevant ones by which ciphertexts changed). Loosening this would need explicit product/security sign-off, not an assumption. Still not done.

## Implementation status

**Done.** The derive-once/pass-as-parameter design from "Scoped fix" above is implemented:

- `Manager.Crypto.encrypt(data:using:)` / `decrypt(data:using:)` and `Data.encrypt(using:)` / `decrypt(using:)` (`Crypto+Manager.swift`) — sibling primitives that take an already-derived key instead of deriving one. The original `Data.encrypt()`/`Data.decrypt()` extensions, used at dozens of other call sites app-wide, are untouched.
- `Group.members(atDepth:usingKey:)`, `refreshCiphertext(usingKey:)`, `purgeMember(_:usingKey:)`, `purgeMembersFromDuressDepths(_:usingKey:)` (`Group+Model.swift`) — new overloads alongside the existing no-key signatures, which now delegate to them after deriving their own key via a new `Self.requireKey()` helper. `reencryptAllDepths` and `encryptedSlots(for:)` (both already `private`, no external callers) take the key directly rather than needing an overload. `setMembers` (behind `addMember`/`removeMember`) derives its own key once internally — no external signature change.
- `ContactManager.cleanUpGroupDuressMembership` (`ContactManager+Classification.swift`) derives the key once and reuses it across every group in the batch, instead of once per slot.
- New `GroupError.keyUnavailable` case — thrown immediately if derivation fails, so the batch aborts rather than silently skipping the mandatory ciphertext refresh (see the security review's fail-loud requirement).
- **No existing call site changed.** Every one of the ~90 existing calls to `members(atDepth:)`, `addMember`, `removeMember`, `refreshCiphertext`, `purgeMember`, `purgeMembersFromDuressDepths` across tests and production UI (`GroupDetailV3.swift`, `Group+FormV3.swift`, `Contact+Manager.swift`, `Contact+Manager+Groups.swift`) is untouched.

**Test coverage added** (`GroupKeyedReencryptionTests` in `GroupModelTests.swift`), per the security review's required coverage:
- Parity — `usingKey:` variants produce identical plaintext round-trip results to the no-key overloads.
- Wrong-key defensive — a mismatched key fails closed (empty result), doesn't crash, doesn't return real data.
- Fail-loud — derivation failure throws `GroupError.keyUnavailable` rather than proceeding.
- **Not added:** a single-derivation call-count test (asserting the batch derives exactly once, not once per slot). `Group`/`ContactManager` construct `Manager.Key()` directly rather than through an injected `KeyManagerProtocol` — consistent with the rest of the codebase's existing convention, but it means there's no seam to count derivation calls without adding new DI wiring, which was judged out of scope for this pass.

**Verification performed:** full `OccultaTests` suite on iOS 18.6 simulator — 594 passed, 9 pre-existing failures confirmed unrelated (identical failures reproduced against the unmodified codebase; all in Forward Secrecy/PQ-fallback and Shard Manifest suites, none touching `Group`/`ContactManager`/`Crypto+Manager`), 0 regressions.

**Not verified — requires a physical device:** the actual wall-clock improvement. Secure Enclave is unavailable on Simulator, so the parity and wrong-key tests above satisfy their `secureEnclaveAvailable()` guard and skip on this environment (matching this test file's existing convention for all encrypted round-trip tests) — they were not exercised against real Keychain/SE round-trips here. Re-running the original Instruments Time Profiler trace on-device, on the same toggle that showed the 27-second severe hang, is the remaining step to confirm the fix collapses it as expected.

**Related finding, now also fixed:** `ContactManager.deleteContact` (`Contact+Manager.swift`) had the identical pattern — `forEachGroup { $0.purgeMember(identifier) }`, deriving the hybrid key fresh per group rather than once for the whole deletion. Same shared engine as the classification path, same fix: `deleteContact` now derives the key once (throwing `GroupError.keyUnavailable` on failure, same fail-loud requirement as `cleanUpGroupDuressMembership`) and calls `purgeMember(identifier, usingKey: key)`. No signature change — `deleteContact`'s own signature and every existing call site are untouched; only its internal group-purge call changed. Existing `DeleteContactPurgesGroupsTests` (3 tests) verified unaffected; full suite re-run showed the same 594 passed / 9 pre-existing-unrelated failures as before this addition.

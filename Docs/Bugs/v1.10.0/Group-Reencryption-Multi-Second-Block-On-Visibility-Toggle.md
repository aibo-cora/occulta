# Marking a contact private/safe blocks the main thread for several seconds

**Status:** confirmed, not fixed. UX mitigation applied (loading state + re-tap guard on the toggle, `Occulta/UI/Tabs/Contacts/v2/TrustCheckV2.swift`, `HideDestinationV2`) — the underlying block is still there, just visible now instead of silent. Found while wiring the Trust Check "Hide/Mark safe" toggle to reach an already-hidden contact for the first time (previously the option disappeared once a contact was hidden, so this path was never exercised from the UI).

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

## Why this wasn't caught earlier

The old `ContactFormV2` "Private contact" toggle called the identical `setVisibility` path and would have hit the identical cost — this is not something Trust Check introduced. It's more visible now because Trust Check made the "mark safe again" direction reachable for an already-hidden contact for the first time (the entry used to disappear once `isSensitive` was true, so re-toggling off was never exercised through this UI at all), surfacing a cost path that existed but had gone unexercised.

## What was and wasn't done here

**Done:** `HideDestinationV2`'s toggle now sets `isApplying = true` and disables itself (showing a `ProgressView` instead) for the duration of the call, wrapped in `Task { @MainActor in ... }` so SwiftUI gets a chance to paint that state before the blocking work starts. This does **not** move the work off the main thread — `ContactManager` is not `nonisolated`, and this project defaults to `SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor` project-wide, so the call stays MainActor-isolated regardless of the `Task` wrapper. The UI will still be unresponsive for the same 5+ seconds; the only change is that it now shows a spinner and can't be re-triggered mid-save, instead of looking hung with a silently queueable second pass.

**Not done — deliberately out of scope for this pass:**

1. **Caching the derived hybrid key across a batch of `encrypt()`/`decrypt()` calls.** Would cut the real work from O(n) SE/Keychain round-trips to O(1) per `reencryptAllDepths` pass (or per app session, depending on cache scope), but touches the core crypto path used throughout the app (`Data.encrypt()`/`Data.decrypt()` are called from dozens of call sites) and needs careful review given the project's "no vulnerabilities, forensic trace clean" bar — key lifetime, cache invalidation on key rotation, and memory exposure all need explicit design, not a quick patch.
2. **Actually backgrounding `setVisibility` off the main thread.** Would require restructuring `ContactManager`'s SwiftData access (a `ModelContext` is not safely shared across threads/actors as-is) — a larger architectural change, not a toggle-level fix.
3. **Scoping `forEachGroup` to only groups the toggled contact actually belongs to**, if the camouflage requirement can tolerate that (it currently can't — the doc comment on `cleanUpGroupDuressMembership` is explicit that every group must show a diff on every save, precisely so membership-relevant groups can't be distinguished from irrelevant ones by which ciphertexts changed). Loosening this would need explicit product/security sign-off, not an assumption.

Any of the three above would meaningfully reduce or eliminate the block; none were attempted here.

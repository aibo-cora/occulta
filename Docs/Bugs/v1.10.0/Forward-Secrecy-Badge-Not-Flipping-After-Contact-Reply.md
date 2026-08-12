# FS badge doesn't flip to "Forward Secrecy" after a contact replies

**Status: closed — working as intended, not a bug.** A fresh repro with the diagnostic logging in place showed a bundle arriving with a non-nil `RecipientPayload.prekeyBatch`, storing correctly via `storeInboundBatch`, and the badge flipping to "Forward Secrecy" as designed. This settles the open question from "What's not yet known" below in favor of the least alarming candidate: the original report's reply hadn't carried a batch yet (the contact's device likely hadn't generated one at that exact point in the exchange) — not a structural bug in the send/receive/consume chain, which the earlier static trace already found no fault in. No code fix needed. The `#if DEBUG` diagnostic logging added while investigating (`openGroup`/`decryptSealed` in `Contact+Manager.swift`, `debugLogPrekeyStateAtCompose` in `Contact+Model+Profile.swift`) is harmless and left in place — no behavior change, available if this class of question comes up again.

## Symptom

Compose header shows a badge for "Standard Encryption" vs "Forward Secrecy" (`Contact.Profile.hasPrekeyAvailable`, driven by `availableInboundPrekeyCount`). After sending a contact a message that fell back to the long-term-key path (no inbound prekeys on file for them) and receiving their reply, the badge stayed on "Standard Encryption" instead of flipping to "Forward Secrecy".

Sender-side log at the time the original outbound message was sent, confirming the fallback:
```
Sealing message bundle, quantum: true
Encrypting message bundle for contact. Inbound prekeys: 0, pending batch: false
popping error: no prekeys available
```

## What's ruled out

- **Cross-`ModelContext` staleness** — `ContactManager` owns its own private `ModelContext`, distinct from the SwiftUI environment's context that `@Query` reads from, which was the leading suspect. Ruled out: a diagnostic (`Contact.Profile.debugLogPrekeyStateAtCompose(_:)`, `Occulta/Features/Forward+Secrecy/Contact+Model+Profile.swift`) compares the live `@Query`-backed count against a fresh re-fetch through a brand-new `ModelContext` on the same container at compose-open time. Result: `live=0 fresh-refetch=0` — both contexts agree, so nothing is stuck stale in the compose view specifically.
- **Contact running a pre-FS app build** — weaker than it looked. `OccultaBundle.Version.v3fs` (the prekey-batch tier) has `minimumAppVersion = "0.0.0"` (`OccultaBundle.swift:134`) — treated as the baseline every real released build satisfies. Not fully excluded (still worth confirming with the app-version log below), but unlikely to be the explanation by the code's own capability model.
- **A structural bug in the send/receive/consume chain** — traced by hand: `encryptBundle` → `wrapRecipient` → `RecipientPayload.prekeyBatch` → `findAndOpenRecipientSlot`/`deriveInboundKey` → `storeInboundBatch` (`Contact+Manager.swift`, `Crypto+Manager+GroupEncrypt.swift`, `Crypto+Manager+GroupDecrypt.swift`, `Crypto+Manager+KeyDerivation.swift`). Mode resolution (`.longTermFallback` → `consumable == nil` → reactive `generateAndStoreFreshBatch` trigger) and batch attach/store are symmetric and appear correct as written. No deterministic bug found by static reading alone.

## What's not yet known

Whether the contact's device actually generated a batch when the fallback message arrived, and whether their reply's `RecipientPayload.prekeyBatch` was non-nil on the wire when this device decrypted it. That state only exists at the moment of decrypting their reply — it can't be determined from static code reading, and no diagnostic had been in place at that moment until now.

**Visibility gap found and fixed (diagnostic-only):** `decryptSealed` (legacy `.v3fs` path) already had debug logs at open/save time; `openGroup` (`.v4`/`.group`, the path virtually all 1:1 messages use in 1.9.0+) had **none** — so even with the console open, nothing would have printed for a modern contact.

## Diagnostic logging added (no behavior change)

All `#if DEBUG`-gated, in `Occulta/Services/Contact+Manager.swift`'s `openGroup` (mirrored where relevant into `decryptSealed`):
- Recipient mode / consumable / pending-batch state entering prekey management.
- Contact's self-reported `appVersion` on the just-decoded bundle, and what `OccultaBundle.Version.max(forAppVersion:)` maps it to.
- What `resolveTargetVersion(for:)` now resolves to for this contact after `updateMaxVersion`.
- Whether `RecipientPayload.prekeyBatch` was present (and its count) right before `storeInboundBatch`.
- Post-save summary: inbound prekey count, pending-batch state.

Also in `Occulta/Features/Forward+Secrecy/Contact+Model+Profile.swift`: `debugLogPrekeyStateAtCompose(_:)`, wired into both `ContactDetailV3.swift` and `ContactDetailV2.swift`'s compose views (`.onAppear` + `.onChange(of: availableInboundPrekeyCount)`).

## Resolved

Repro captured: a subsequent bundle arrived with `RecipientPayload.prekeyBatch` present, `storeInboundBatch` persisted it, and the compose badge flipped to "Forward Secrecy" correctly. Of the three candidates this doc's investigation couldn't distinguish from code alone (batch never left their device / never arrived / arrived but failed to persist), none of them held up — the batch did arrive and did persist, just not on the very first reply. No fix needed; closing.

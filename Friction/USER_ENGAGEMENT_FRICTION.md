# User Engagement Friction Report

Fact-based analysis derived from source code. No assumptions.  
Date: 2026-04-30

---

## The core engagement funnel

```
Download → Onboarding → Add contact → Exchange keys → Compose → Encrypt → Send via another app → Recipient opens .occ
```

---

## Stage 1: Onboarding

The onboarding is 4 screens with a **"Skip" button visible from screen 1**
(`OnboardingView.swift`). Users can enter the app without reading any of it.
Screen 2 introduces the 25 cm UWB exchange requirement — users who skip never
see it. First interaction after onboarding is an empty contacts list with no
guidance on what to do next.

---

## Stage 2: Adding a contact

Contact form has a silent failure:

```swift
// TODO: Display a warning that a contact could not be saved
// Contact+Form.swift:207
```

Save errors produce no user-facing feedback. The contact appears unsaved with
no explanation.

---

## Stage 3: Key exchange — highest drop-off point

### Hardware gate

`isExchangePossible` checks
`NISession.deviceCapabilities.supportsPreciseDistanceMeasurement`.
Failure renders:

> "Key exchange is not supported by your device's hardware capabilities.
> Device must have UWB chip."

Red text, no alternative path. iPhone 10 and earlier are permanently blocked.

### Permission friction

Two iOS system permission dialogs must be accepted before exchange can
proceed — Nearby Interaction and Local Network. The UI pre-warns about both,
but each interrupts the flow with a system prompt outside the app's control.

### Physical constraint

Both devices must be ≤ 25 cm apart. Enforced in `NISessionDelegate` —
`distance.isLessThanOrEqualTo(0.25)` — exchange only proceeds when satisfied.

### Watchdog failure

A 30-second `DispatchSourceTimer` fires `exchangeFailed(.uwbUnavailable)` if
no NI updates arrive (`Exchange+Manager.swift:227`). The error alert requires
users to:

1. Navigate to Settings → Privacy → Location Services → System Services →
   toggle "Networking & Wireless" off then on
2. Restart both devices
3. Try again

This is a 3-step hardware-level recovery flow that requires both participants
to coordinate simultaneously.

### Silent key save failure

In `ExchangeResult`, the Confirm button's `catch {}` block is empty:

```swift
Button("Confirm") {
    do {
        try self.contactManager?.update(key: self.key, for: self.identifier)
    } catch {
        // silently swallowed
    }
    self.dismiss()
}
```

If `contactManager?.update(key:for:)` throws, the key silently fails to save.
The exchange appears to succeed but the contact has no key.

### Diceware verification

After every successful exchange, users must verbally compare a multi-word
Diceware phrase. This is a required manual step with no timeout or skip —
the key is only saved after tapping Confirm.

---

## Stage 4: Composition

`ComposableMessage` uses `@State private var messages: [Occulta.File] = []`.
Messages are **not persisted**. Navigating away from the view during
composition — a phone call, switching apps, the screen timing out — silently
destroys all unsaved content. There are no drafts.

---

## Stage 5: Encrypt and send

After composing, the user taps "Encrypt," waits for async processing (no
progress indicator beyond the button being present), and receives a system
`UIActivityViewController` with every available iOS share target. The
resulting `.occ` file must be manually routed to the recipient through a
separate app. There is no in-app delivery.

---

## Stage 6: Recipient opens .occ

The recipient must have the sender as a contact with an active key. If they
don't, `buildOwnedBasket` fails — the file cannot be decrypted. There is no
"sender not found" message visible in the inbound flow.

The delivery mechanism routes through:

```
ShareExtension → app group container → URL scheme occulta://inbound?session=<uuid>
```

If the main app is not installed or the URL scheme fails, the file is written
to the container with no fallback.

---

## Feature flag state

| Flag | State | Implication |
|------|-------|-------------|
| `enableShamirShardSharing` | `false` | SSS entirely hidden from users |
| `usePassphraseToExportContacts` | `false` | No contact export exists |
| `allowSynchingBetweenDevices` | `true` | Flag is on but entitlement is disabled — feature silently does nothing |
| `signature` | `false` | Signing tab hidden |

`allowSynchingBetweenDevices` being `true` in `features.plist` while disabled
in entitlements is a live inconsistency — the flag reports the feature as
enabled but it cannot function.

---

## What doesn't exist

| Missing capability | Evidence |
|---|---|
| Message history | `@State var messages` — resets on every view appearance |
| Inbox | No persisted inbound message store in any model |
| Notifications | No `UNUserNotificationCenter` usage found |
| Contact export | Gated behind `usePassphraseToExportContacts = false` |
| Device migration | `allowSynchingBetweenDevices` disabled in entitlements |
| Key rotation UI | Documented as unresolved in `OccultaApp.swift:13` |
| SSS shard acknowledgement | `TODO Phase 2` in `ShardCustody+Manager.swift:105` — `.acknowledge` is never sent; every `ShardRecord` stays `.sent` permanently |

---

## Summary

| Stage | Friction level | Root cause |
|---|---|---|
| Onboarding | Low | Skippable; UWB requirement not seen by skip users |
| Add contact | Low–Medium | Silent save failure with no user feedback |
| Key exchange | **High** | Hardware gate + proximity gate + permission gate + 30s watchdog + silent save failure |
| Composition | Medium | No draft persistence; state lost on navigation |
| Encrypt + send | Medium | No progress indicator; manual file routing through external app |
| Receive + open | Medium | Sender must be a known contact; multi-hop inbound delivery can silently fail |

The single highest-friction point is key exchange: hardware-gated,
proximity-gated, permission-gated, with a fragile 30-second window and a
silent save failure on success. Everything downstream is blocked until it
succeeds. The second-highest friction is the absence of persistence — no
message history, no drafts, no delivery confirmation — making every session
stateless from the user's perspective.

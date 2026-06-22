# Group Messaging — Critical Analysis Findings

**Status:** All resolved — reflected in SPEC.md  
**Against spec version:** Design complete, pre-implementation

---

## Critical — Security Gaps

### F-01 · `wrappedKey` seal has no AAD

`AES.GCM.seal(sessionKey, using: wrappingKey)` is specified with no additional authenticated data. Nothing binds the wrapped session key to this specific group or this specific recipient. An attacker who compromises one recipient's wrapping key could substitute an arbitrary `sessionKey` into any `Recipient` slot for any group and pass authentication.

**Resolution:** AAD for each `wrappedKey` seal must be `groupID || recipientFingerprint`.

---

### F-02 · Prekey replenishment is undefined for group sends

In single-recipient bundles, the sender embeds their fresh prekeys for the recipient inside the shared `SealedPayload`. For group bundles there is one `SealedPayload` — per-recipient prekey batches cannot go inside it. The spec says "prekey batch if needed" without resolving this contradiction.

If left undefined, contacts in frequent group sends will exhaust their prekey stock and silently fall back to long-term ECDH, losing forward secrecy without any signal to the user.

**Resolution:** Prekey replenishment moves from `SealedPayload` into each `Recipient.wrappedPayload` as a `RecipientPayload` struct carrying both the session key and an optional `PrekeySyncBatch`. Each recipient's wrappedPayload is encrypted under their own per-recipient wrapping key — only they can derive it — so the prekey batch is as isolated as it was in the single-recipient path. Group sends now fully support prekey replenishment on a per-recipient, per-threshold basis.

---

### F-03 · Long-term fallback path undefined

The spec assumes prekeys are always available for all group members. A contact whose prekey pool is exhausted has no defined handling. The encrypt flow would fail or behave inconsistently across implementations.

**Resolution:** Reuse the existing per-recipient `SecrecyContext.mode` to signal the path used for each key wrap:
- Prekey available → `secrecyContext.mode = .forwardSecret`, ephemeral P-256 keypair + contact prekey
- Prekey exhausted → `secrecyContext.mode = .longTermFallback`, long-term identity ECDH

The outer `bundle.secrecy.mode = .group` is unchanged. The receiver reads each `Recipient.secrecyContext.mode` to determine which unwrap path to take. No new fields needed — `SecrecyContext` already carries all required fields.

---

## Significant

### F-04 · Version gating implementation is vague

The spec states `maxBundleVersion >= groupCapable` without defining what byte value `groupCapable` maps to. `maxBundleVersion` is a `UInt8` derived from `Version.max(forAppVersion:)`, which requires a `Version` case and a wire byte. Adding a version case solely for group capability is inconsistent with the existing guidance ("do not add version cases for features").

**Resolution:** Add a new encrypted field `encryptedAppVersion: Data?` to `Contact.Profile`. When a bundle is received, store the raw `appVersion` string from `SealedPayload` encrypted alongside the existing `maxBundleVersion`. Group eligibility checks `encryptedAppVersion.compare("1.9.0", options: .numeric) >= .orderedSame`. This decouples wire format versioning from feature capability gating. Requires a SwiftData lightweight migration (new optional column, no migration plan needed).

---

### F-05 · Thread mode behaviour for groups is undefined

The group detail mockup shows the compose style toggle (Quick / Thread). In single-recipient, thread mode opens a persistent draft thread of accumulated messages. With no message persistence in this release, thread mode has no defined meaning for groups.

**Resolution:** Thread mode is excluded from group detail in v1.9.0. The compose style toggle is not shown in the group detail view. Quick compose only.

---

### F-06 · 32-member cap justified by the wrong precedent

The cap is described as consistent with `AppLayerConfig.maxVerifierCount = 32`, which was chosen to bound the number of PIN layers — a completely unrelated constraint. The cap should stand on its own terms.

**Resolution:** Reframe: 32 members is sufficient for personal, family, and small-team use cases within Occulta's threat model (proximity-exchanged contacts, out-of-band delivery). The fixed capacity also directly determines the forensic footprint per group (64 × 64 bytes = 4 KB). If use cases requiring larger groups emerge, the cap can be raised in a future release with a SwiftData migration. The `AppLayerConfig` coincidence is incidental and should be removed from the justification.

---

## Privacy

### F-07 · `groupID` is a stable cleartext traffic correlation vector

`GroupEnvelope.id` (a stable UUID) appears cleartext in every bundle for this group across all transports (SMS, WhatsApp, Signal, email). An interceptor who collects multiple bundles over time can cluster them by `groupID` without decrypting anything, revealing group communication frequency and timing.

**Resolution:** Document as an accepted known property. Mitigations (rotating group ID per send) would break AAD binding and add complexity disproportionate to the threat — the sender controls bundle distribution via chosen transport.

---

### F-08 · Bundle size independently leaks recipient count

Each `Recipient` struct is fixed size. Total bundle size reveals N recipients to a passive observer without parsing the structure. This is redundant with the already-accepted "N recipient slots visible" property.

**Resolution:** Document as accepted, same tradeoff as slot count visibility.

---

## Forensic Trace

### F-09 · SQLite WAL not addressed

On every full array recompute, prior array states are written to the SQLite WAL file until the next checkpoint. A filesystem-level examiner can potentially recover encrypted prior states. Since all values are encrypted blobs, this reveals only that writes occurred, not their content.

**Resolution:** Document as accepted — pre-existing condition for all contact and config data. Note that a WAL checkpoint on app launch would limit accumulation.

---

### F-10 · `encryptedCreatedAt` precision unspecified

If stored at millisecond precision, an examiner with the local DB key sees exact creation timestamps, potentially correlating group creation with other observable events.

**Resolution:** Store as second-precision `TimeInterval` (truncate milliseconds before encrypting). Document in spec.

---

## User Friction

### F-11 · Version gate UX gives no actionable signal

A newly exchanged contact (key exchange done, no bundle received yet) appears grayed out in the member picker with no explanation. Users will not understand why a trusted contact cannot be added. The version is learned only when a bundle is RECEIVED from the contact — sending to them does not reveal their version.

**Resolution:** Member picker uses two sections — eligible and ineligible. Ineligible contacts are non-interactive with a section header explaining the reason:
- Version unknown (`encryptedAppVersion == nil`): "Ask them to send you a message"
- Version too old (`encryptedAppVersion < "1.9.0"`): "Ask them to update Occulta"
- Mixed: "These contacts need a newer version of Occulta or haven't messaged you yet"

---

### F-12 · Prekey burn rate — resolved by F-02

Group sends consume prekeys per recipient and replenish them on the same threshold logic as single-recipient sends, via `RecipientPayload.prekeyBatch`. No additional documentation needed.

---

### F-13 · No delivery confirmation

The sender has no mechanism to confirm any recipient received or decrypted the bundle. Recipients on 1.8.x receive the bundle but cannot decrypt it — the sender never knows. This is inherent to the out-of-band, no-persistence design.

**Resolution:** Document as a known limitation for v1.9.0.

---

### F-14 · Duress layer group setup has no guidance

The spec notes there is no UX obligation to populate duress groups, but provides no guidance for users who want a plausible duress scenario. Groups in the duress layer start empty, which may be conspicuous to a sophisticated coercer who knows the user actively uses groups.

**Resolution:** Document that duress group setup is the user's responsibility, consistent with the existing secure mode model (contacts, vault entries also require deliberate duress-layer population). A setup prompt or guidance screen is out of scope for v1.9.0 but noted as future work.

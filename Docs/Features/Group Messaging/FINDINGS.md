# Group Messaging — Critical Analysis Findings

**Pre-implementation status:** All resolved — reflected in SPEC.md  
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

**Resolution:** Use the existing `maxBundleVersion: Data?` on `Contact.Profile`. Add a new `Version` case `.groupCapable` with `minimumAppVersion = "1.9.0"`. Group eligibility checks `resolveTargetVersion(for: contact) >= .groupCapable`. No new field, no SwiftData migration.

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

---

---

# Post-Implementation Security Review — v1.9.0

**Status:** Open  
**Scope:** `v1.9.0/group-messaging` branch — all new files and changed files  
**Date:** 2026-06-27

---

## HIGH — Security Vulnerabilities

### F-15 · Sender identity not bound to authenticated content

**File:** `OccultaBundle.swift:487–490`, `Crypto+Manager+GroupEncrypt.swift:54–70`, `Contact+Manager.swift:1344`  
**Confidence:** 9/10

`senderFingerprint` and `fingerprintNonce` are explicitly excluded from the outer AES-GCM AAD (documented in `OccultaBundle.swift` line 57: *"not in the AAD and not encrypted"*). The outer AAD for a group bundle is:

```
"v4" || JSON({mode:"group", ephemeralPublicKey:"", prekeyID:nil}) || groupID.uuidString
```

`identifyOwner(for:)` finds the sender purely by computing `SHA256(contact.pubKey || bundle.fingerprintNonce) == bundle.senderFingerprint` — a check over two unauthenticated cleartext fields with no AES-GCM protection.

**Attack:** A group member (Eve) intercepts a bundle from Alice. She replaces `fingerprintNonce` with a fresh nonce and sets `senderFingerprint = SHA256(BobPublicKey || newNonce)`. The outer `AES.GCM.open` succeeds unchanged. `identifyOwner` matches Bob. If Eve is herself a group recipient, she can also re-derive her own per-recipient slot (which is keyed on Eve's ECDH with Alice, not Alice's identity) — so the outer ciphertext opens and the message is delivered with Bob attributed as sender, not Alice. Any group member can produce a cryptographically indistinguishable re-attribution of any observed bundle to any other member.

**Fix:** Include `senderFingerprint || fingerprintNonce` in the outer ciphertext AAD, or bind the sender's long-term public key inside the `SealedPayload` where it is covered by the session key's GCM tag.

---

## MEDIUM — Security Vulnerabilities

### F-16 · `longTermFallback` group bundles are indefinitely replayable

**File:** `Crypto+Manager+KeyDerivation.swift:39–48`, `Contact+Manager.swift:1366–1384`, `OccultaBundle.swift:462–469`  
**Status:** Accepted — documented limitation  
**Confidence:** 9/10

For the `longTermFallback` path (`contactPrekey == nil`), the per-recipient wrapping key is `HKDF(ECDH(senderLongTermPriv, recipientLongTermPub))` — fully determined by the two parties' stable identity keys, with no per-bundle randomness. `RecipientPayload` contains only `sessionKey: Data` and `prekeyBatch: PrekeySyncBatch?` — no timestamp, nonce, sequence number, or bundle identifier. After `openGroup` succeeds on this path, `consumable == nil` and no bundle ID or seen-nonce is recorded.

**Actual exposure (narrower than originally stated):** Shard bytes — the sensitive vault content — are already protected. When no prekey is available, `encryptBundle` drops shard operations from the bundle entirely and sends only the basket on `longTermFallback` — no shard content travels without FS. The FS paths are immune independently: prekey consumption deletes the SE private key, so second delivery throws `recipientSlotNotFound`.

What remains replayable on the fallback path is:

- **Regular messages (basket-only):** re-delivery produces a duplicate in the UI. No state mutation, no confidentiality impact.
- **`custodyManifest` / `expectedShards` metadata:** these piggyback on regular message bundles and cannot be separated without breaking the send. Requiring FS for bundles that carry them would be equivalent to requiring FS for all messages, eliminating the fallback path entirely. Replaying a `custodyManifest` makes an owner believe a trustee still holds shards they have since deleted; replaying `expectedShards` keeps a trustee holding shards the owner has since revoked. Impact is vault state staleness — liveness and correctness, not confidentiality.

**Why a seen-nonce store was not adopted:** The cost (persistent store with expiry policy, restart-safe, cleanup surface area) is disproportionate to the residual risk. No secret material is exposed by replay. The practical replay window is also bounded: an attacker must intercept the bundle on its chosen out-of-band transport (SMS, WhatsApp, Signal, email) and re-deliver it to the recipient — this is not a passive read-only capability.

**Accepted limitation:** Fallback-path bundle replay can produce duplicate messages and transiently stale vault custody state. It cannot expose shard content or forge sender identity (F-15 fix). Future mitigation: a persistent nonce cache with a rolling 30-day expiry window, if vault metadata staleness proves operationally significant.

---

### F-17 · Group layer enforcement is UI-only

**File:** `Contact+Manager.swift:1021`, `GroupDetailV3.swift:33–35`  
**Confidence:** 8/10

`encryptGroupBundle(basket:groupID:recipients:)` accepts an arbitrary `[String]` identifier list with no layer verification. The service layer cannot distinguish a real-layer send from a duress-layer send. The enforcement of "send only to the active depth layer's members" lives entirely in `GroupDetailV3.resolvedMembers`, which reads the layer from `RoutingDepth(rawValue: self.security.currentDepth)`.

In Occulta's coercion threat model, a UI bug (wrong layer variable, race on depth change during navigation, or a future refactor) would silently include real-layer contacts in a duress-layer bundle. The service layer would encrypt and ship it with no indication anything is wrong.

**Fix:** `encryptGroupBundle` should accept a `layer: RoutingDepth` parameter and fetch the group's members for that layer internally via `group.members(in: layer)`, removing the caller-supplied identifier list as the authoritative source of truth.

---

### F-18 · Cleartext group UUID in TLV section defeats `encryptedID` protection

**File:** `WireHandle.swift:70–75`, `Crypto+Manager+GroupEncrypt.swift:105–109`, `Group+Model.swift`  
**Confidence:** 9/10  
**Status:** Fixed

`Group+Model.swift` stores the group UUID as `encryptedID` (AES-GCM encrypted at rest) with the documented rationale: *"Stored encrypted so a forensic examiner cannot correlate the DB record with a cleartext GroupEnvelope.id seen in an intercepted bundle."* The TLV encode/decode implemented in this branch puts the same UUID in cleartext in TLV section `0x01` of every `.occ` file.

**Result:** A forensic examiner who obtains the device (and its DB key for contact names) AND has previously intercepted `.occ` files can read the groupID from each bundle's TLV section and directly correlate which SQLite `Group` record corresponds to which intercepted traffic — the specific protection `encryptedID` was designed to prevent. The cleartext UUID also lets a passive observer without the device determine which `.occ` files belong to the same group.

**Fix applied:** `GroupEnvelope.id: UUID` replaced with `blind: Data` + `blindNonce: Data`. `blind = HMAC-SHA256(key: groupID.rawBytes[16], msg: blindNonce)` where `blindNonce` is 16 fresh random bytes per bundle. Both the outer AAD and each per-recipient wrappedPayload AAD use `blind` in place of `groupID.uuidString`. The stable `groupID` is stored inside the AES-GCM-encrypted `SealedPayload.groupID` field only. The receiver reads `groupID` from the decrypted payload — no cleartext exposure, no group scan required. Cross-group replay resistance is preserved because `blind` is derived from `groupID`; a different group produces a different blind under the same nonce.

---

### F-19 · Silent entropy failure in `randomFiller()` produces zero-byte slots

**File:** `Group+Model.swift:183`  
**Confidence:** 9/10  
**Status:** Fixed

`randomFiller()` discards the return value of `SecRandomCopyBytes`:

```swift
private static func randomFiller() -> Data {
    var data = Data(count: slotSize)   // zero-initialized
    _ = data.withUnsafeMutableBytes {
        SecRandomCopyBytes(kSecRandomDefault, slotSize, $0.baseAddress!)
    }                                  // status silently discarded
    return data
}
```

If `SecRandomCopyBytes` fails (low-entropy conditions immediately after first boot, memory pressure, `errSecParam`, `errSecAllocate`), the function returns 156 zero bytes. Real AES-GCM member slots (12-byte random nonce + 128-byte ciphertext + 16-byte tag) are statistically non-zero. Zero filler is trivially distinguishable, reducing a forensic examiner's search to only non-zero slots and revealing actual group membership.

The rest of the codebase handles this correctly: `SecrecyContext.generateNonce()` tests `errSecSuccess` and throws `BundleError.entropyUnavailable`. `randomFiller()` follows neither pattern.

**Fix:**

```swift
private static func randomFiller() throws -> Data {
    var bytes = [UInt8](repeating: 0, count: slotSize)
    guard SecRandomCopyBytes(kSecRandomDefault, slotSize, &bytes) == errSecSuccess else {
        throw GroupError.entropyUnavailable
    }
    return Data(bytes)
}
```

Propagate `throws` through `freshFillerArray()` and `encryptedSlots(for:)`. Add `GroupError.entropyUnavailable`.

---

### F-20 · Recipient fingerprints enable passive group membership confirmation

**File:** `Crypto+Manager+GroupEncrypt.swift`, `Crypto+Manager+GroupDecrypt.swift`  
**Confidence:** 8/10  
**Status:** Fixed

Each `OccultaBundle.Recipient` in the cleartext TLV section carried `fingerprint = SHA256(recipientLongTermPubKey || fingerprintNonce)` and `fingerprintNonce` (16 bytes), both unauthenticated and unencrypted. Any party who holds a target contact's long-term public key (obtained through a prior key exchange) could iterate the recipient list of any intercepted bundle, compute `SHA256(targetPubKey || entry.fingerprintNonce)` for each entry, and confirm whether the target is a group member — with no decryption, no key derivation, and no server interaction.

**Fix applied:** `fingerprint` and `fingerprintNonce` removed from `Recipient`. The receiver finds their slot by trial-decryption: for each slot, derive the inbound wrapping key from the slot's `secrecyContext` and attempt `AES.GCM.open(wrappedPayload, authenticating: blind)`. The first slot that opens is theirs. Per-recipient AAD simplified from `blind || fingerprint` to `blind`. `GroupEnvelope.version: UInt8 = 1` added as a forward-compatibility field for future format changes without a new TLV section type.

---

## BUGS

### F-21 · `saveGroup` add-before-remove fails silently at capacity

**File:** `Group+FormV3.swift:220–225`  
**Severity:** Medium (silent data loss)

```swift
for identifier in self.selectedIdentifiers.subtracting(current) {
    try group.addMember(identifier, in: self.layer)   // runs first
}
for identifier in current.subtracting(self.selectedIdentifiers) {
    try group.removeMember(identifier, in: self.layer)
}
```

If a group has 32 members (capacity) and the user attempts any swap (add 1, remove 1), `addMember` throws `capacityExceeded` before any remove runs. The `catch` block prints to console and then unconditionally calls `self.dismiss()` — the form closes with no error shown and no changes saved. The user has no indication the save failed.

**Fix:** Remove members first, then add. Or compute the final target set and call a single `setMembers` replacing both loops.

---

### F-22 · Duplicate TLV section `0x01` last-wins with no error

**File:** `WireHandle.swift:73`  
**Severity:** Low (correctness / future-proofing)

The TLV parse loop unconditionally overwrites `groupEnvelope` on each `0x01` section seen:

```swift
if sectionType == 0x01 { groupEnvelope = sectionBytes }
```

A bundle with two `0x01` sections silently uses the second one. If a serialization bug ever produces duplicate sections, the wrong envelope is used with no diagnostic. A valid second section with the same `groupID` but an empty `recipients` array would cause all recipients to see `recipientSlotNotFound`.

**Fix:** Throw on a duplicate `0x01` section rather than silently overwriting.

---

### F-23 · Silent entropy failure in `AppLayerConfig.randomFiller()` produces zero-byte filler slots

**File:** `AppLayerConfig+Model.swift:274`, `AppLayerConfig+Model.swift:282`, `AppLayerConfig+Model.swift:290`  
**Confidence:** 9/10  
**Status:** Deferred — fix in a dedicated branch

Identical pattern to F-19 (`Group+Model.swift`), but in `AppLayerConfig`. Both `randomFiller()` and `verifierFiller()` discard the return value of `SecRandomCopyBytes`:

```swift
private static func randomFiller() -> Data {
    var data = Data(count: fillerSize)
    _ = data.withUnsafeMutableBytes {
        SecRandomCopyBytes(kSecRandomDefault, fillerSize, $0.baseAddress!)
    }
    return data
}
```

If `SecRandomCopyBytes` fails, both methods return zero-initialized `Data`. The affected arrays:

- `sealedBlobSlots` (filler: 30 zero bytes) — a forensic examiner can distinguish live blob slots from filler without the SE key, revealing which layers are active.
- `layerSequenceNumbers` (filler: 30 zero bytes) — same, reveals which sequence number slots are populated.
- `sealedNormalVerifiers` / `sealedDuressVerifiers` (filler: 53 zero bytes) — reveals which verifier positions are real vs filler, indicating the number of active PIN layers.
- `pinEnabledPerDepth` (fallback in `ensurePadded` and `pinEnabledFillerArray`) — 30 zero bytes, distinguishable from encrypted `UInt8` values.

**Fix:** Make `randomFiller()` and `verifierFiller()` throw on non-`errSecSuccess`. Propagate `throws` through `randomFillerArray()`, `verifierFillerArray()`, `pinEnabledFillerArray()`, `clearBlobSlot(at:)`, `clearSequenceNumber(at:)`, `clearAllBlobMetadata()`, and `ensurePadded()`. Use `try!` in `init()` and in `Manager.Security.init()` migration path (both non-throwing contexts where entropy failure is non-recoverable). Add `AppLayerConfigError.entropyUnavailable`. Update `Manager+Security.swift` deactivation call sites to propagate `throws`.

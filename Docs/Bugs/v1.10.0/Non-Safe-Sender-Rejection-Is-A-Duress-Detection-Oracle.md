# Rejecting a known contact's bundle under duress is itself a duress-detection oracle

**Status:** open, unscoped. Found while scoping shard-custody items 4–5 (`Shard-Custody-Not-Cleaned-Up-On-Contact-Deletion.md`) — surfaced when checking whether a coercer-controlled second device sending a real shard could be used to detect duress mode. Turned out to be broader than shards: this applies to every inbound bundle type gated by `passSecurityControl`, and it isn't something a decoy/fabrication mechanism of any kind can fix, because it's a live protocol-behavior difference, not a display or content problem. A "allow-and-confine" mitigation for contacts added during duress was explored (see bottom section) — closes only half the oracle, and surfaces its own new prerequisites (a second, exact-match visibility model for contacts; a related pre-existing contact-leak gap; an unrelated `handleReplace` ownership-check fix) — not implemented.

## The mechanism

`passSecurityControl` (`OccultaApp.swift:733`):
```swift
private func passSecurityControl(identifier: String) throws {
    if self.security.isRestricted && self.contactManager.isSafeContact(identifier) == false {
        throw ContactManager.Errors.noPublicKeyToEncryptWith
    }
}
```

This runs inside `buildOwnedBasket` for every `.v3fs`/`.v4` bundle, right after `identifyOwner(of:)` succeeds (a real fingerprint match against a real, known contact) and before `openGroup`/`decryptSealed` are ever called. It's documented as C1 in `forensic-trace-avoidance.md` and is working exactly as designed: sensitive content never gets decrypted while restricted.

The problem is what happens on either side of that branch:

- **At depth 0 (`isRestricted == false`):** the check never applies. A bundle from any known contact — safe, sensitive, doesn't matter — is always processed normally.
- **At any duress depth (`isRestricted == true`):** a bundle from a known contact who is *not* marked safe at this exact depth is rejected outright, with a surfaced "not addressed to you" error, before decryption ever starts.

Real mode has exactly one failure category: "we don't recognize this sender at all" (`identifyOwner` fails to find any fingerprint match — happens regardless of depth, for genuinely unknown senders, corrupted bundles, stale keys, etc.). Duress mode adds a second, depth-conditional failure category that doesn't exist in real mode at all: "we know exactly who this is, and we're refusing it right now." Both categories currently surface the identical error text, which gives some cover against a naive single test from an unknown sender — but gives essentially none against a sender the tester already knows for certain is genuinely paired with the device.

## The attack

A coercer needs one thing: a contact identity that is unambiguously, provably paired with the victim's device — an existing contact, or one force-paired live during the coercion itself (this app's only pairing mechanism is physical UWB proximity, so a coercer with physical control of the victim already has what's needed). They send anything from that identity while the victim is unlocked at the duress depth being tested, and observe the result:

- **Accepted, processes normally →** consistent with real mode.
- **Rejected, "not addressed to you" →** this outcome is *only* reachable when `isRestricted == true`. A real, known contact's message cannot produce it at depth 0, under any circumstance. One rejection from a contact already proven to be genuinely paired is close to conclusive; a second contact tested the same way removes essentially all doubt.

This isn't specific to shard-custody bundles — `passSecurityControl` gates the same way for ordinary messages, identity-challenge traffic, and shard/custody operations alike, since it runs once per bundle before any type-specific branching.

## Why decoy content doesn't help

This was found while evaluating whether a fabricated `CustodianRecord` (the items 4–5 decoy-custodian design) or the confirmed real-shard ceiling-visibility behavior would close the gap the user described — a coercer sending a real shard and it never showing. Neither does, for the same reason: both only affect what's already stored and how it's *displayed*. This attack never reaches display at all — the bundle is rejected at the protocol level, before any content exists to show or hide. No amount of authored decoy content changes what `passSecurityControl` does with an inbound bundle from a non-safe sender.

## The fundamental tension

This isn't a bug in the implementation sense — `passSecurityControl` does exactly what C1 was built to do, and removing the check would mean sensitive content actually gets decrypted and potentially displayed under duress, which is worse. The tension is structural: the app needs sensitive content to be **cryptographically unreachable** under duress (C1's whole purpose), which requires treating non-safe senders differently than safe ones — and any difference in treatment is a potential behavioral signal. Reachability-blocking and behavioral indistinguishability pull in opposite directions here; satisfying one fully likely costs something on the other.

This is the same underlying tension already identified from the opposite direction in "Duress signaling for shard custody" (`Shard-Custody-Not-Cleaned-Up-On-Contact-Deletion.md`) — that exploration found a *proposed* covert-acceptance-signal mechanism unsafe for essentially this reason. This finding shows the tension is already live in a mechanism that's shipped and marked fixed (C1), not just a risk in something hypothetical.

## Open questions — not yet decided

- **Silent drop instead of a surfaced error?** Matching C2's "zero processing, no visible trace" approach more closely — a non-safe sender's bundle could be silently discarded rather than producing a visible error. This would remove the sharp accept/reject signal a coercer can currently read directly off the screen, at the cost of the legitimate account holder also getting no feedback when a message genuinely doesn't apply to the current depth (which happens for ordinary, non-adversarial reasons too — messages addressed to a different depth's persona, stale bundles, etc.). Not evaluated for its own side effects yet.
- **Is there any way to make the two failure categories statistically indistinguishable**, not just textually identical? E.g., could real depth-0 mode be made to occasionally reject a known contact's message for unrelated legitimate reasons at a similar rate, so a duress-depth rejection isn't categorically anomalous? Untested, and may not be achievable without cost elsewhere.
- **How much of this can actually be closed, versus accepted as a residual limit** on what this app's threat model can defend against (an adversary with physical control who can force live protocol tests, as opposed to only inspecting data at rest)? Worth an explicit decision rather than leaving it implicitly unresolved.

No fix is scoped here — this needs a decision on direction before any implementation is attempted.

## Proposed mitigation explored: allow-and-confine for duress-added contacts

**The idea:** rather than rejecting a non-safe sender's bundle, allow a contact *added while already in duress* to operate fully — messages, shard ops, everything processed normally, no visible rejection — but confine that contact (and anything tied to it, e.g. custody shards) so it's invisible from the real layer and from every other depth. Directionally consistent with how the rest of the app already handles duress content: `VaultEntry` decoys and `Group`'s independent per-depth membership both already accept creating real, functioning entities at a duress depth that never surface elsewhere. Analyzed below; not implemented.

### How much of C3 this actually closes — only half

This only covers contacts *added during* the duress session. C3's strongest form uses a contact who's already known — paired before the coercion began, or someone the coercer has separate leverage over — who simply isn't pre-classified safe at this depth. That contact still hits `passSecurityControl` and still gets rejected exactly as today; this proposal doesn't touch that path, and extending "allow all operations" to *existing* non-safe contacts would undermine C1's whole purpose (sensitive content actually gets decrypted under duress). So: closes the "coercer brings their own phone and pairs live" attack — plausibly the most likely one in practice, since this app's only pairing mechanism is physical UWB proximity and a coercer with physical control already has what that requires — but leaves the "coercer uses an existing contact" variant fully open.

### The technical obstacle: `Contact.Profile`'s visibility model can't express "hidden at 0, visible at duress depth N"

`Contact.Profile.visibleThroughDepth` uses **ceiling** semantics (`Manager+Security.swift:1330`, `value >= depth`): a contact stamped `N` is visible at every depth `0..N`. Depth 0 is the root that sees everything; duress depths see a shrinking subset going deeper. There is no ceiling value that means "invisible at 0, visible only at N" — 0 is always ≤ any non-negative N, so every representable contact under this model is visible at depth 0. Confining a contact to exactly one duress depth needs **exact-match** semantics instead — the pattern already used for `VaultEntry.visibleThroughDepth` and `globalTrusteeDepth`, both introduced precisely because ceiling couldn't express per-depth-independent content. This is a second, different visibility rule that would need to coexist with the existing ceiling rule used for safe/sensitive contact classification, not a small tweak to the current field.

### A closely related, pre-existing gap this surfaces

Contact creation today (`Contact+Manager.swift:206-207`) already stamps a contact added while at a duress depth with `ceiling = currentDepth`:
```swift
let depthValue = currentDepth == 0 ? Int.max : currentDepth
newContact.visibleThroughDepth = try JSONEncoder().encode(depthValue).encrypt()
```
The doc comment there reads "hidden from deeper layers" — true, but only half the story. Per the ceiling formula, that same contact is *also already visible at depth 0 and every shallower depth* in the shipped app today. The comment's phrasing suggests the original intent was closer to full depth confinement, but the ceiling model can't deliver the other half of it, and that gap appears to have gone unnoticed independent of this proposal. Right now, anyone a user is forced to add during duress persists into their real contact list the next time they unlock normally — worth an explicit decision regardless of whether the proposal above moves forward.

### One consequence that comes free, if the visibility fix lands

`CustodyShard` has no depth field of its own — `Vault+Tab.swift`'s display filter derives visibility entirely from the owner contact's own `isDisplayable(_:)`. So once `Contact.Profile` supports real exact-match confinement, shard visibility for that contact's rows is correct automatically — no separate shard-specific plumbing needed.

### A separate, pre-existing vulnerability this proposal would make significantly easier to exploit

`ShardCustodyManager.handleReplace` (`ShardCustody+Manager.swift:148`) verifies the *new* attribute's signature but not that the *old* shard being replaced belongs to the *same sender*:
```swift
let allShards = try self.decryptAllCustodyShards()
for decoded in allShards where decoded.payload.signedAttribute.id == oldID {
    self.modelContext.delete(decoded.row)
}
```
The deletion is keyed purely on `oldID`, a UUID, with no ownership check. Today this requires being a pre-classified safe contact to reach at all. This proposal would let *anyone the coercer can force-pair on the spot* reach the same code path — meaningfully lowering the bar for griefing another contact's real custody shard, given a real `attributeID` obtained via manifest traffic or otherwise. Needs its own fix (scope the deletion to `ownerContactIdentifier == senderIdentifier`) before broadening who can reach shard mutation, independent of the duress-visibility question.

### Net assessment

Directionally right, not ready to implement. Needs: (1) a new exact-match visibility mechanism for contacts, distinct from and coexisting with the current ceiling model, (2) an explicit decision on the pre-existing "duress-added contacts already leak to depth 0" gap this surfaces, (3) the `handleReplace` ownership fix before broadening who can reach shard mutation, and (4) clarity that it only closes the "newly force-paired identity" half of C3, not the "existing contact" half.

### The new field: `originDepth`, and why it needs to be separate from `visibleThroughDepth`

Settled shape for point (1) above — a new encrypted `Int` field on `Contact.Profile`, `originDepth`, exact-match semantics. No `-1` sentinel needed (unlike `globalTrusteeDepth`): `0` already means exactly what's wanted — "created at the real depth, no confinement, defer entirely to the existing `visibleThroughDepth` ceiling" — and any `N > 0` means "born at duress depth N, confined to exactly N, full stop." One short-circuit added to `Manager.Security.isVisible(_:atDepth:)` (`Manager+Security.swift:1330`), before the existing ceiling check:
```swift
static func isVisible(_ contact: Contact.Profile, atDepth depth: Int) -> Bool {
    if let origin = decodedOriginDepth(contact), origin > 0 {
        return origin == depth
    }
    // ...existing, untouched ceiling logic
}
```
`isSafeContact`/`passSecurityControl` need no changes — both already call through `isVisible`.

Whether a single field could do both jobs was raised directly, and checked against the actual test suite rather than argued abstractly: `PINManagerTests.swift:590`, `isSensitive_atDepth1_checksCurrentDepthValue`, has a real contact ("b") marked safe at depth 0, then reclassified from *within* depth 1 to "hidden beyond here" — and the tested, shipped expectation is that "b" stays visible at *both* 0 and 1 afterward. That's a range satisfied from a single classification action, which exact-match cannot express — it only ever matches one depth. Ceiling also has to represent "visible at every depth" for safe contacts, which needs the same kind of `>=` special-casing regardless of how the field is arranged. Both of those are real, currently-shipped behaviors this analysis is not proposing to touch.

**Recorded disagreement, not resolved:** there's real doubt about whether two fields are actually needed here, versus this being the necessary consequence of a design decision worth re-examining — the disagreement was raised as: *a contact does not have to be visible at different depths, only its own.* On that view, "safe" contacts appearing at multiple depths might itself be the thing to question, rather than something to preserve by construction — pushing toward a model closer to `Group`'s independent per-depth membership (each appearance at a depth is its own explicit record) instead of one scalar ceiling number implying a range. That's acknowledged as a significantly larger change than adding `originDepth` — not something to undertake as part of closing C3 — but it's an open question about the *existing* `visibleThroughDepth` design, not something this analysis has settled, and worth its own dedicated discussion before more is built on top of the current ceiling model.

### Migration plan for `originDepth`, if this proceeds

1. Stamp `originDepth = currentDepth` at both existing `Contact.Profile` creation call sites (`Contact+Manager.swift:~207, ~390`), alongside the existing `visibleThroughDepth`/`globalTrusteeDepth` stamps.
2. Backfill migration (`PQmigration.swift`, its own independent do/catch in `migrate()`, matching the other three migrations already there): every existing contact gets `originDepth = encrypt(0)` unconditionally. `0` is the only safe default — there's no historical record of what depth any existing contact was actually added at, and `0` guarantees no existing contact is ever retroactively confined by a wrong guess.
3. Thread `originDepth` through the same three places `globalTrusteeDepth` already goes: `Contact+Model+Reencrypt.swift`'s `reencryptAllFields`, `SecureMode+LayerStore.swift`'s `LayerContact` (with a `0` fallback for blobs predating the field), and activation Step 4/5 + deactivation Step 4 + `restoreContact`.
4. New test suite mirroring `GlobalTrusteeDepthTests.swift`: creation-time stamping, backfill idempotency, activation/deactivation preservation, and the two behavioral cases that matter most — a contact created at depth 1 is visible only at depth 1, and a contact created at depth 0 with an adjusted ceiling (the `isSensitive_atDepth1_...` scenario) is completely unaffected.

Not yet implemented — still blocked on the same open items in "Net assessment" above, plus the unresolved two-fields question.

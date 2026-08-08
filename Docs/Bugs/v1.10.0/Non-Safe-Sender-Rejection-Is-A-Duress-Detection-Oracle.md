# Rejecting a known contact's bundle under duress is itself a duress-detection oracle

**Status:** in progress. Final design settled 2026-08-08 (see "Final design: `passSecurityControl` removed entirely" near the bottom): the rejection-based oracle closes completely and unconditionally — `passSecurityControl`'s restriction-gated rejection is removed for every contact, not special-cased by type, and `onDuress`'s unconditional discard of queued files (C2) is brought in line to match. The active-tester variant (duress-origin or existing-contact) closes with zero residual risk, since the coercer is always the author of what gets decrypted back to them. What remains is narrower and different in kind: a deliberately accepted, timing-bounded **content-confidentiality** risk for the passive variant only (a real, unaware third party's message rendering on screen during a coercion window) — not a detection oracle, since there's no longer any sender-dependent rejection signal to detect. **Implemented so far (`d0d75b5`, `314cf18`):** `originDepth` (floor semantics) — the display-visibility half, keeping duress-origin contacts out of the real depth-0 view — and the `handleReplace` ownership-check fix it depends on, since restriction no longer gates shard-mutation reachability for anyone. **Not yet implemented:** `passSecurityControl`'s removal and C2's `onDuress` change — the actual rejection-oracle closure itself. A 2026-08-07 pass verified the "wording parity" open question below is already satisfied by the shipped code and closed one adjacent gap found while verifying it — see "2026-08-07 — Wording parity verified..." near the bottom. Found while scoping shard-custody items 4–5 (`Shard-Custody-Not-Cleaned-Up-On-Contact-Deletion.md`) — surfaced when checking whether a coercer-controlled second device sending a real shard could be used to detect duress mode.

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

### A passive variant: receiving a genuine message while restricted, no coercer device needed

The attack above assumes the coercer actively sends a probe from a device they control. A weaker-effort, more opportunistic version needs no device at all: a real, unaware third-party contact sends the victim an ordinary message during the coercion window, while the phone is in the coercer's hands and a duress depth is active. If that contact isn't marked safe at this depth, the identical rejection fires — and the coercer, simply watching the screen, sees the same accept/reject signal without having to force-pair or send anything themselves.

The concrete trigger for this variant doesn't even require the phone to be unlocked when the message arrives: a file received while locked is queued in `pendingFileData` (`OccultaApp.swift:505-508`) and automatically drained the moment a duress PIN succeeds and the phase becomes `.unlocked` (`OccultaApp.swift:285-291`) — so the rejection (or its absence) can surface unprompted, immediately after a coerced unlock, with no action from the victim at all. This is the same underlying mechanism and same fix surface as the active-tester attack, just a different, easier-to-encounter trigger — not a separate bug.

### A narrower related case: two known parties coerced together — corrected after initial overstatement

**Initial framing, later walked back:** a couple traveling together, both coerced simultaneously (e.g. a joint checkpoint stop), one forced to message the other — reasoned at first to be a "definite" tell, stronger than the general active-tester case, because the observer has direct, first-hand knowledge of both the send action and the intended recipient. That removes the "maybe it was misaddressed" cover story the passive-receipt variant relies on, since that story only works when the observer doesn't independently know who the sender meant to reach.

**The correction: this doesn't fire as generally as first claimed, because send-side selection and receive-side rejection are gated by the identical function.** The wife can only select her husband to message him if he's *visible in her own contact list at her current duress depth* — and that visibility check is not a separate, more permissive mechanism from the one `passSecurityControl` uses. `ContactsListV2.swift:39` filters the list she picks from via `self.security.isDisplayable($0)`, and `isDisplayable` is `Manager.Security.isVisible(_:atDepth:)` (`Manager+Security.swift:1326-1327`) — the exact same ceiling function `isSafeContact`/`passSecurityControl` call on the *receiving* end. If she's hidden him from herself at her current depth, he simply doesn't appear for her to select — there's no bundle to reject because there's nothing to send in the first place.

This narrows the scenario to a specific, asymmetric condition, not "any coerced couple":

- **Default case (nothing hidden about each other):** a contact added under ordinary circumstances gets `ceiling = Int.max` — visible at every depth by default (`Contact+Manager.swift:206-207`). An ordinary couple with no reason to hide each other would typically both be safe on each other's devices by default, so the message just goes through normally on both ends. **No tell.**
- **Symmetric hiding (e.g. protecting the relationship itself from a shared coercive party):** if both have reason to hide each other, both directions are likely mutually hidden. She can't select him either — the observable outcome is "he's not in her contacts," an absence with the same weak, ambiguous signal value as no message arriving at all, not an explicit on-screen rejection. **No tell of the strong kind.**
- **The actual failure case — asymmetric, one-directional hiding:** she hasn't hidden him (he's selectable, she sends), but he *has* hidden her at his current depth. Only this specific mismatch produces the on-screen rejection with full observer certainty of intent. This is a real, reachable misconfiguration — nothing in the app prompts two people who trust each other to keep their classifications of one another consistent — but it requires a deliberately asymmetric setup, not something that falls out of ordinary joint travel.

**UX mitigation shipped for the asymmetric-misconfiguration case (not the oracle itself):** a cross-device sync mechanism to keep two people's classifications of each other consistent was considered and rejected — it would mean transmitting local security state between devices (something this app deliberately never does), and a timestamp-based version specifically reintroduces the exact diff-comparison forensic tell `purgeCustody`'s re-sealing was built to close elsewhere. Instead, `SecureModeSetupFlow.swift`'s final review step (`SummaryView`) now shows a plain-text reminder — "Ask each hidden contact to mark you as sensitive too — otherwise a message between you could reveal Secure Mode is active on your device" — whenever `sensitiveCount > 0`, right next to the "N contacts will be hidden" line and the existing "deleting the app is unrecoverable" warning. No data exchange, no new field, nothing transmitted — just a nudge for both people to independently set the same state on their own devices. Reduces how often the *accidental* asymmetric case arises; does nothing for a coercer who deliberately exploits an existing mismatch, which is unchanged and still open.

**Net:** the underlying mechanism is real and worth recording — it's a previously-undocumented instance of "The attack"'s already-open "coercer uses an existing contact" case (line 76 above), reachable via two coerced parties rather than a coercer-controlled device — but it is not a distinct, broader-severity scenario, and the original "definite tell for any coerced couple" framing was wrong. No change to open/unscoped status; no new fix surface beyond what's already tracked.

## Why decoy content doesn't help

This was found while evaluating whether a fabricated `CustodianRecord` (the items 4–5 decoy-custodian design) or the confirmed real-shard ceiling-visibility behavior would close the gap the user described — a coercer sending a real shard and it never showing. Neither does, for the same reason: both only affect what's already stored and how it's *displayed*. This attack never reaches display at all — the bundle is rejected at the protocol level, before any content exists to show or hide. No amount of authored decoy content changes what `passSecurityControl` does with an inbound bundle from a non-safe sender.

## The fundamental tension

This isn't a bug in the implementation sense — `passSecurityControl` does exactly what C1 was built to do, and removing the check would mean sensitive content actually gets decrypted and potentially displayed under duress, which is worse. The tension is structural: the app needs sensitive content to be **cryptographically unreachable** under duress (C1's whole purpose), which requires treating non-safe senders differently than safe ones — and any difference in treatment is a potential behavioral signal. Reachability-blocking and behavioral indistinguishability pull in opposite directions here; satisfying one fully likely costs something on the other.

This is the same underlying tension already identified from the opposite direction in "Duress signaling for shard custody" (`Shard-Custody-Not-Cleaned-Up-On-Contact-Deletion.md`) — that exploration found a *proposed* covert-acceptance-signal mechanism unsafe for essentially this reason. This finding shows the tension is already live in a mechanism that's shipped and marked fixed (C1), not just a risk in something hypothetical.

## Open questions — not yet decided

- ~~**Silent drop instead of a surfaced error?**~~ **Decided 2026-08-07: no — keep the surfaced alert in all cases.** See "Wording parity verified" below: the two failure categories already produce identical, surfaced error text, and that was judged sufficient cover for a single observation. Silent-drop-everywhere was considered and rejected as a broader behavior change (legitimate users lose feedback for ordinary misdirected/corrupted files at real depth 0 too) than this pass's scope called for.
- **Is there any way to make the two failure categories statistically indistinguishable**, not just textually identical? E.g., could real depth-0 mode be made to occasionally reject a known contact's message for unrelated legitimate reasons at a similar rate, so a duress-depth rejection isn't categorically anomalous? Untested, and may not be achievable without cost elsewhere. **Still fully open** — this is now the primary residual gap for the passive-receipt variant above: identical wording defeats a single observation, not a pattern noticed over extended physical control (one contact's messages consistently failing while others' don't).
- **How much of this can actually be closed, versus accepted as a residual limit** on what this app's threat model can defend against (an adversary with physical control who can force live protocol tests, as opposed to only inspecting data at rest)? Worth an explicit decision rather than leaving it implicitly unresolved. Still open.

No fix to the core oracle is scoped here — this needs a decision on direction before any implementation is attempted.

## 2026-08-07 — Wording parity verified; adjacent legacy-path plaintext gap fixed

Prompted by re-scoping this finding around the passive-receipt variant above. Two things were checked against the shipped code, not just reasoned about abstractly:

**Wording parity — already true, confirmed by direct code read, not just design intent.** Both failure categories — a genuinely unrecognized sender (`identifyOwner`/`decrypt(data:)` finding no match, `Contact+Manager.swift:952,1461`) and a known-but-restricted sender (`passSecurityControl` throwing) — resolve to the identical `ContactManager.Errors.noPublicKeyToEncryptWith` and hit the identical catch clause and displayed text in `processInboundFile` (`OccultaApp.swift:535-537`). This holds across both bundle formats and both entry points into that function — the interactive `onOpenURL` open and the `pendingFileData` auto-drain-on-unlock path described above. No divergent wording was found anywhere in this chain.

**Decision: keep the alert surfaced everywhere, not just because wording matches.** Considered moving to silent-drop (matching C2) for the auto-drain trigger specifically, since an unprompted popup right after a coerced unlock is a more conspicuous event than the same popup after a deliberate file-open — but decided against changing behavior at all, in any case. No code change resulted from this question.

**Found while verifying, fixed as a small adjacent item:** the legacy bundle path (`OccultaApp.swift`, `default` case in `buildOwnedBasket`) decrypts a sensitive contact's message into memory via `decrypt(data:)` *before* `passSecurityControl` ever runs — unlike the v3fs/v4 path, which gates before any decryption happens. This isn't reorderable the way it first looked: legacy-format bundles have no fingerprint pre-check the way `OccultaBundle` does, so a successful decrypt is the only way the sender is identified at all — the checkpoint structurally cannot run before plaintext exists for this format. The fix that's actually achievable: the plaintext is now zeroed (`withUnsafeMutableBytes`/`memset`, matching the existing convention at e.g. `SecureMode+LayerStore.swift:149`) immediately if the checkpoint rejects it, rather than lingering unzeroed until ARC deallocates it. Doesn't change what a coercer or examiner observes (same error, same text, same UI either way) — pure memory hygiene for the legacy path, tightening the C1 "never decrypted while restricted" invariant that already held for the modern path. No dedicated test added — `buildOwnedBasket`/`passSecurityControl` are private to `RootView` and have no existing unit-test seam, consistent with the rest of this file.

**Net effect on this finding:** the core oracle (both variants) remains open and unscoped, exactly as before. This pass closed out the wording-parity open question specifically (already true, decision made not to change surfacing behavior) and fixed one small adjacent memory-hygiene gap found in the process.

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

Superseded by floor semantics and the no-composition decision below — see "originDepth revised" and "Final design" further down for what actually shipped instead of this exact-match sketch. Kept here for the reasoning trail.

**Implemented (`d0d75b5`).** `originDepth` shipped with floor semantics (`depth >= origin`, per the correction below, not the exact-match sketched above), threaded through creation stamping, the backfill migration, `reencryptAllFields`, and activation/deactivation — see "originDepth revised" and "Final design" below for the shipped shape. One deviation from the migration plan as originally written: `LayerContact` does **not** carry an `originDepth` field. Working through `restoreContact`'s fallback value surfaced that any contact reaching the blob at all is provably never duress-origin — activation's Step 4 short-circuit excludes them before the blob-sealing branch is ever reached — so there was no real value to thread through; `restoreContact` writes the 0 sentinel directly instead. Verified: clean build, full `OccultaTests` suite (700 tests; the two that failed on one full run — `VaultManagerLifecycleTests/locksAfterInactivity`, `EncryptBundleShardFallbackTests/fallbackDropsAllThreeShardFields` — both passed clean in isolation on retry, pre-existing flakiness unrelated to this change).

**Not yet implemented:** `passSecurityControl`'s removal, C2's `onDuress` change, and the `handleReplace` ownership fix's integration with this — `originDepth` is the visibility half only. See "Final design" below for what's left.

## 2026-08-08 — Scoping pass on the core oracle: two findings narrow the live surface, a fix proposed but not implemented

Prompted by returning to scope the core oracle itself (not the allow-and-confine mitigation above, which only ever addressed half of it). Two things were checked directly against shipped code rather than reasoned about abstractly, and both narrow what's actually still live.

**Finding 1 — the locked-then-duress-unlock trigger is already fully silent, resolving the "(or its absence)" hedge in the passive-variant section above.** `onDuress` (`OccultaApp.swift:354-358`) clears `pendingFileData` with no dialog and no processing:
```swift
onDuress: {
    self.pendingFileData = nil
    self.contactManager.syncShareIndex()
    self.appScreen.pinDidSucceed()
}
```
`processInboundFile`'s own doc comment confirms it: *"Never called from `onDuress` — that path discards."* So a file queued while the phone was locked, then cleared by a coerced duress-PIN unlock, already produces zero observable difference between "nothing was ever sent" and "a known-but-restricted sender's file was dropped." **This half of the passive-receipt variant was already closed by C2's existing design** — it just hadn't been confirmed against the code before now, and the doc's original wording left it as an open possibility rather than a settled one.

**Finding 2 — both failure categories already share one error case, not just matching wording.** A genuinely-unknown sender (`identifyOwner` finds no fingerprint match) and a known-but-restricted sender (`passSecurityControl` throwing) both resolve to `ContactManager.Errors.noPublicKeyToEncryptWith`, caught by a single `catch` clause in `processInboundFile` (`OccultaApp.swift:535-537`). No new branch is needed to tell them apart for a fix — they're already unified before that catch runs.

**What's actually still live, after both findings:** only the case where the app is already unlocked at a duress depth when a file arrives via `onOpenURL` → `processInboundFile` directly — covers both the active-tester probe (line 27 above) and a passive message arriving while the coercer is watching an already-unlocked screen (the other half of the passive variant, line 36 above).

**Proposed fix — not yet implemented.** Suppress the alert for `noPublicKeyToEncryptWith` specifically when `self.security.isRestricted`, matching the behavior `onDuress` already ships for the sibling locked-path trigger:
```swift
} catch ContactManager.Errors.noPublicKeyToEncryptWith {
    if !self.security.isRestricted {
        self.errorMessage = "Could not find this file's owner's public key. It is either corrupted and you need to update the app and try again or the message was not addressed to you."
        self.showError = true
    }
    // Restricted: stay silent, matching onDuress's already-shipped behavior for
    // the locked-path equivalent of this exact failure.
}
```
Not "silent-drop everywhere" (already rejected 2026-08-07 above) — silent only for the one error case that can only fire while restricted; depth-0 behavior is byte-for-byte unchanged. Since `passSecurityControl` gates every bundle type through this single entry point, one change covers messages, identity-challenge traffic, and shard/custody operations alike.

This revisits the 2026-08-07 "keep the alert surfaced everywhere" decision above, on grounds that decision didn't have in view: an equivalent silent-on-restricted behavior is already shipped and accepted for the locked-path trigger, so extending it to the live-unlocked trigger is consistency with existing, accepted precedent, not a new UX regression class.

**What this would close:** the definitive on-screen artifact for the live-unlocked trigger of both remaining variants — a coercer forcing a probe, or watching a passive message arrive, at a duress depth would see nothing, identical to nothing having been sent.

**What this would not close, and why — see residual-risk discussion.** Real depth-0 mode still never produces this specific silence; only duress depths do. Open question #2 from the original scoping ("statistically indistinguishable, not just textually identical") remains fully open and is now the entire residual gap, not one of several. Not yet decided whether to pursue that or accept this as the residual limit — see conversation record for the discussion.

## 2026-08-08 — `originDepth` revised: floor semantics, not exact-match; sensitivity is a no-op for duress-origin contacts

**Implemented as designed below (`d0d75b5`)** — see the "Migration plan for `originDepth`" section above for the shipped-vs-sketched delta (`LayerContact` doesn't carry the field after all).

Revisits the "allow-and-confine" design above (the "The new field: `originDepth`" section) after walking through a concrete scenario: a contact added while already at duress depth 1, later marked sensitive, then the operator activates another nested Secure Mode layer and moves to depth 2. Two problems with the original sketch surfaced from that walk-through, both now resolved:

**Problem 1 — exact-match breaks on the exact scenario `originDepth` exists to handle.** The original design used `origin == depth`. A contact created at depth 1 would already fail that check at depth 2 — rejected, reproducing the same on-screen tell this mechanism was built to remove, the moment the operator goes one layer deeper than where the contact was created. **Fixed: floor semantics instead of exact-match** — `depth >= origin` — visible/processable at its origin depth and everything nested deeper than it, hidden only shallower (depth 0, and anything above its origin). Depth 0 is always excluded since `origin > 0` by construction for any duress-created contact, so the core confinement goal (never leak to the real view) holds under floor semantics exactly as it did under exact-match.

**Problem 2 — silence is also a tell.** A parallel proposal to fix the live-unlocked oracle by suppressing the rejection alert (see the section above) was explicitly rejected in favor of this mechanism instead, on the reasoning that an app going silent when it should be working normally is itself anomalous — genuinely processing the bundle is better cover than faking normalcy through silence, because it isn't faked.

**Resolved: does sensitivity classification still apply on top of the `originDepth` floor?** Considered composing the two — `origin` sets a floor, `visibleThroughDepth` still sets a ceiling on top of it, so marking a duress-origin contact "sensitive" would cap its visibility at deeper layers exactly like it does for any other contact. Walked through against the same depth-1-then-depth-2 scenario: under composition, marking the contact sensitive while at depth 1 stamps `visibleThroughDepth = 1`, and the contact is rejected again at depth 2 — silence or an explicit dialog either way, both already rejected as tells. **Decided: no composition. For a duress-origin contact (`originDepth > 0`), sensitivity classification (`visibleThroughDepth`) has no effect on accept/reject or display, full stop — the floor is the only check that runs.** There is nothing real behind a duress-origin contact for a coercer to leak by keeping it fully operational at every depth from its creation onward; restricting it later serves no protective purpose and only reintroduces the tell. Scope confirmed narrow and deliberate: this applies **only** to contacts with `originDepth > 0`. Real, pre-existing contacts — sensitive or not — are completely unaffected; `passSecurityControl`/`isSafeContact` keep rejecting them under duress exactly as today. Extending always-accept to real sensitive contacts was considered and explicitly rejected — it would mean actual sensitive content gets decrypted while restricted, the exact outcome C1 exists to prevent, and reopens a risk this doc already reasoned was worse than the oracle itself.

Corrected design for `Manager.Security.isVisible(_:atDepth:)`:
```swift
static func isVisible(_ contact: Contact.Profile, atDepth depth: Int) -> Bool {
    if let origin = decodedOriginDepth(contact), origin > 0 {
        return depth >= origin   // floor only — sensitivity classification never applies here
    }
    // ...existing, untouched ceiling logic for contacts without a duress origin
}
```
`isSafeContact`/`passSecurityControl` still need no changes — both already call through `isVisible`.

**Bonus, confirmed:** floor semantics also close the "closely related, pre-existing gap" flagged earlier in this doc (a duress-added contact leaking into the real depth-0 view) as a side effect — `0 >= origin` is false whenever `origin > 0`, so no separate fix is needed for that gap once this lands.

**Open, not yet decided:** since "Mark sensitive" becomes inert for a duress-origin contact, should that control be hidden/disabled in the UI for such a contact, or left present but silently doing nothing? Leaving it visible-but-inert risks a different, smaller confusion (a toggle that appears to do something and doesn't); hiding it is an extra UI conditional. Minor compared to the rest of this design, not blocking it, but worth a decision before implementation.

**Residual, explicitly accepted, not a gap in this design:** a coercer sophisticated enough to understand the classification model and deliberately test the depth-1-mark-sensitive-then-depth-2 sequence *would* have hit a rejection under the composed design — but that path no longer exists at all now that sensitivity is a no-op for these contacts, so this concern from the prior turn's discussion is resolved by the no-composition decision, not merely accepted as residual.

**Scope reminder, since superseded — see the final design below.** The line originally here said this only closed half of C3, leaving the "existing contact" and passive-receipt variants untouched. That's no longer the boundary of this design — see the next section for why, and for the actual remaining scope.

## 2026-08-08 — Final design: `passSecurityControl` removed entirely, not special-cased per contact type

Extends the `originDepth` design above to its logical conclusion, reached by working through who actually learns something new in each remaining variant of C3.

**The active-tester variant — both flavors, duress-origin *and* existing-contact — closes completely, with zero residual risk, not a probabilistic one.** A coercer running this test is, by construction, the author of the probe message: either it's a duress-origin contact they created themselves, or it's an existing contact whose identity they control and are composing from directly. Either way, decrypting and displaying that message back to them reveals **nothing they don't already know** — there's no information asymmetry to protect in the first place. This isn't "the window is short so they probably won't notice"; there is no exposure at all, at any window length, because the content is theirs.

**That reframes what "accept the short window" is actually for: only the passive variant** — a genuine, unaware third-party contact's real message arriving while a duress depth is active and the coercer happens to be watching. This is the one case with real information asymmetry: content the coercer doesn't already know, and a receipt-time reveal (`OccultaApp.swift:530`, `openedFileContents` bound straight to `.sheet(item:)`) that displays it immediately, unconditionally, the moment decryption succeeds. Here, "coercion windows like border checks are usually short" is doing real, deliberately risk-accepting work — this is the one place C1's absolute "never decrypted while restricted" guarantee is being traded for a timing-based one, and that trade is explicit and deliberate, not incidental.

**Given that, the design is: remove `passSecurityControl`'s `isRestricted`-gated rejection entirely, for every contact — real, sensitive, duress-origin, existing, whoever.** No sender that resolves to a known fingerprint is ever rejected differently because of restriction state, at any depth. What's left of the original rejection path is only the case that was never part of the oracle to begin with — a genuinely unrecognized sender (`identifyOwner` finds no fingerprint match at all) — which fails identically regardless of depth and always has, so it carries no depth-dependent signal.

**Consequence: `originDepth` stops being an accept/reject mechanism and becomes purely a display-visibility one.** With nothing left to reject, its only remaining job is keeping a duress-origin contact out of the real depth-0 view (and any depth shallower than its origin) when browsing the contact list or message history — the floor semantics and no-composition-with-sensitivity decisions above are unchanged, just narrower in purpose now.

**C2 changes to match, for consistency, not because it independently needed to.** `onDuress` (`OccultaApp.swift:354-358`) currently discards `pendingFileData` unconditionally rather than processing it — the one remaining place where duress state still produces different behavior from normal unlock. Decided: bring it in line — drain and call `processInboundFile` the same way regardless of which PIN just succeeded, matching `onAuthenticated`'s existing behavior. The locked-then-unlock trigger and the already-unlocked trigger now behave identically.

**Net effect on the rejection-based detection oracle: fully closed, not partially.** There is no longer any scenario where a fingerprint-matched, known sender's bundle is accepted at depth 0 and rejected at a duress depth — the condition C3 depended on doesn't exist anymore. What remains is a narrower, different kind of risk — not a detection oracle (proving duress mode exists), but a **content-confidentiality** risk specific to the passive variant: a real, sensitive contact's genuinely new message can render on screen during a coercion window, once, at the moment it arrives.

**Implementation detail to get right, not yet resolved:** the immediate receipt-time reveal (`openedFileContents`) should be unconditional now, but the *stored* message/thread afterward should still respect the contact's normal depth-visibility classification for any *later* browsing — this is a one-time reveal at the moment of arrival, not a permanent reclassification of that thread as visible-at-this-depth going forward. Needs to be deliberate at implementation time so a coercer doesn't gain standing access to the thread in the message list after the initial popup closes.

**`handleReplace`'s missing ownership check (flagged earlier as a prerequisite for the duress-origin case alone) is now a hard blocker for the whole design, not a narrower one.** With `passSecurityControl` gone entirely, *any* known contact — not just duress-origin ones — can reach shard-mutation code paths under restriction. `ShardCustody+Manager.swift:148`'s `handleReplace` deletes by `oldID` alone with no check that the replacing sender owns the shard being replaced. This must land before or alongside this change, not after.

**Scope, final:** this closes the entire rejection-based oracle (both variants, unconditionally) and narrows the remaining risk to a single, deliberately accepted, timing-bounded content-exposure case — a real sensitive contact's new message during the passive variant. The `handleReplace` fix and the `originDepth` migration plan scoped earlier both still apply, now motivated by the full design rather than half of it.

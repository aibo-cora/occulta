# Rejecting a known contact's bundle under duress is itself a duress-detection oracle

**Status:** open, unscoped. Found while scoping shard-custody items 4–5 (`Shard-Custody-Not-Cleaned-Up-On-Contact-Deletion.md`) — surfaced when checking whether a coercer-controlled second device sending a real shard could be used to detect duress mode. Turned out to be broader than shards: this applies to every inbound bundle type gated by `passSecurityControl`, and it isn't something a decoy/fabrication mechanism of any kind can fix, because it's a live protocol-behavior difference, not a display or content problem.

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

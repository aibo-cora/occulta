# Occulta — Security Review of `release/v1.10.2`

**Date:** 2026-08-12
**Branch:** `release/v1.10.2` (`b149f41`, 40 commits ahead of `develop`)
**Scope:** Diff review of `origin/develop...HEAD` — production Swift, `Info.plist`, `Occulta.entitlements`, and `.github/workflows/ci.yml`. Documentation excluded. Test files read for intent, not audited as targets. **Not a full-codebase pass** — unlike `SecurityReview2026-07-24`, this covers only what this release changes, plus one pre-existing issue that release changes brought to the surface.
**Method:** Single-reviewer pass with direct source reading; every finding traced file:line end-to-end through production code before inclusion. No sub-agent fan-out — the reviewer held the full design context for the diff, including the Secure Mode threat model and the rationale behind each change.

---

## Executive Summary

This release fixes three Secure Mode key-rotation bugs (Bugs 75, 76, 77 in `Docs/Features/Secure Mode/bugs.md`) in which model rows were never re-encrypted during the local DB key rotation and were therefore stranded when the superseded key was deleted.

The review found **one HIGH-severity authentication bypass**, and it is the most consequential item here because of what it silently disabled:

1. 🔴 **The sender-ephemeral-signature enforcement added by the `2026-07-24` review's own remediation has been inert on any install that ever activated Secure Mode.** That gate is keyed on `Contact.Profile.maxBundleVersion`, which was one of the fields never re-keyed — so it reads as "sender too old to sign", and unsigned forward-secret bundles are accepted. The cause is fixed in this release; **the existing damage is not, and cannot be** — stranded values are unrecoverable.

Two further findings are in this release's own new code:

2. 🟡 **Key rotation commits and deletes the old key even when the re-encryption passes were skipped**, silently recreating the exact bug class this release fixes.
3. 🔵 **A conditional WAL checkpoint** contradicts a differential-signal rule the codebase states explicitly elsewhere.

Nothing in the non-Secure-Mode part of the release (entitlements, `Info.plist`, `DraftStore`, CI) introduced a vulnerability; two of those changes are net security improvements, noted at the end.

**Fix priority:** Finding 2 is a one-line change and should land before this release merges. Finding 1 needs a release-note/operational decision rather than a code fix, plus an optional hardening change. Finding 3 is cosmetic-adjacent but cheap.

---

## Findings

### Contacts & Messaging

#### 🔴 HIGH — Stranded `maxBundleVersion` silently disables sender-ephemeral-signature enforcement

- **File:** `Occulta/Services/Contact+Manager.swift:1727` (the enforcement gate), `:1431` (`resolveTargetVersion`, the fail-open fallback)
- **Also implicated:** `Occulta/Data Models/Contact+Model+Reencrypt.swift` (the field's absence from `reencryptAllFields`, fixed in this release), `Occulta/Features/SecureMode/Manager+Security.swift` Step 11 (`deleteSupersededLocalDBArtefacts`)
- **Confidence:** 9/10 — gate, fallback, and capability tier each read directly; the precondition is confirmed present on a real device (the reporting user's install).
- **Status:** 🟠 **Cause fixed in this release. Existing state unfixable — operational decision required.**

**Description.** `openGroup` rejects a forward-secret bundle that carries no `senderEphemeralSignature` only when the sender is known to be capable of producing one:

```swift
if isFSMode, recipientPayload.senderEphemeralSignature == nil,
   Self.resolveTargetVersion(for: sender, using: cryptoOps).isAtLeast(.senderSignatureCapable) {
    throw GroupDecryptError.missingSenderEphemeralSignature
}
```

That capability comes from `Contact.Profile.maxBundleVersion`, one encrypted byte sealed under the local DB key. `resolveTargetVersion` returns `.v3fs` whenever the field will not decrypt — and `.v3fs` is not `senderSignatureCapable`, so the branch is skipped and the unsigned bundle is accepted.

`maxBundleVersion` was in neither `reencryptAllFields` nor `reencryptKeyRecords`. Every Secure Mode activation or deactivation therefore stranded it for **every contact**, and Step 11 deleted the key that could read it.

The consequence is exactly what the `2026-07-24` review warned about in the finding this gate was built to close: *"FS mode's session key never involves the sender's long-term identity — `senderEphemeralSignature` is the actual binding for that mode."* With the gate skipped, that binding is not required, and opening the AEAD proves only that the builder knew a valid `(prekeyID, prekeyPub, ephemeralPub)` triple — not who they are.

**Exploit scenario.** Victim has activated Secure Mode at any point since 1.10.0, so every contact's `maxBundleVersion` is stranded. An attacker who can deliver an `.occ` file — the app's ordinary transport — constructs a forward-secret group bundle attributed to a contact the victim trusts, omitting `senderEphemeralSignature` entirely. The gate does not fire, and the message is accepted and displayed as authenticated from that contact. The residual bar is the one left by the `2026-07-24` fix to finding #1: the attacker still needs prekey material the victim issued to the impersonated contact, so this is not open to arbitrary third parties — but it fully removes the layer added on 2026-08-01 to close that gap.

**Why the fix does not close it.** This release adds `maxBundleVersion` to `reencryptAllFields`, so future rotations preserve it. Already-stranded values cannot be recovered — the hybrid key needs an SE half that is non-exportable and has been deleted. Enforcement stays off per contact until that contact sends a bundle, which rewrites the field under the current key.

**Recommendation.**
1. **Operational:** treat as a release note. Affected users restore enforcement by exchanging one message with each contact — the same action that restores group eligibility (see Bug 77). Consider whether this warrants a more active prompt than a note.
2. **Hardening:** make the gate fail closed on ambiguity. `resolveTargetVersion` collapses "never seen this contact" (`nil`) and "value present but undecryptable" into the same `.v3fs`, so a *lost* capability marker is indistinguishable from one that never existed. These should be separated, and a lost marker should not silently weaken authentication. **Note a conflict introduced by this release:** `reencryptAllFields` now clears undecryptable values to `nil`, which destroys the very evidence that distinction needs. That was the right call for the group-eligibility UX and the wrong one for this gate; if the hardening is adopted, revisit it.

---

### Secure Mode

#### 🟡 MEDIUM — Rotation commits and deletes the old key even when the re-encryption passes were skipped

- **File:** `Occulta/Features/SecureMode/Manager+Security.swift:567` (activation), `:912` (deactivation)
- **Confidence:** 9/10 — control flow read directly; no `else`, no guard, unconditional fall-through to commit.
- **Status:** 🔴 **Open. Introduced by this release.**

**Description.** Both rotation paths wrap the draft, group, and `AppLayerConfig` re-encryption in:

```swift
if let oldKey = try self.keyManager.createHybridLocalEncryptionKey() {
    …
}
```

with no `else`. If derivation returns `nil`, all three passes are skipped and execution falls straight through to `commitStagedLocalDBKey()` and then `deleteSupersededLocalDBArtefacts()`. Groups and `AppLayerConfig` are left sealed under a key that is then destroyed — permanently unreadable, which is precisely Bugs 75 and 76, recreated by the code that fixes them.

**Exploit scenario.** Not attacker-triggered; a silent-failure path. Any condition that makes the Secure Enclave or Keychain briefly unavailable during activation causes the rotation to commit anyway, with no error and no user-visible signal. The blast radius is every group and the entire layer config.

**This contradicts a rule the codebase already states.** `Group.requireKey()` throws `GroupError.keyUnavailable` for this exact situation, documented as: *"Must abort the whole pass rather than proceed with a missing key — silently skipping the mandatory ciphertext refresh would itself be a forensic tell."* This release extended a pre-existing `if let` (the draft pass) to cover groups and config without applying that rule to it.

**Recommendation.** Replace with `guard let oldKey = … else { throw SecurityError.keyDerivationFailed }`. Both sites are already inside the `do`/`catch` that calls `rollbackStagedLocalDBKey()`, so aborting is clean and leaves the canonical key intact and the data readable. One line each.

---

#### 🔵 LOW — Conditional WAL checkpoint contradicts the stated differential-signal rule

- **File:** `Occulta/Features/SecureMode/Manager+Security.swift:1224` (`migrateBlobMetadataKeyIfNeeded`)
- **Confidence:** 8/10 — behaviour is unambiguous; impact is genuinely small.
- **Status:** 🔴 **Open. Introduced by this release.**

**Description.** The blob-metadata migration checkpoints only when it moved something:

```swift
if moved {
    try? self.modelContext.save()
    self.checkpointStore()
}
```

`checkpointStore()`'s own documentation requires the opposite: *"Must run unconditionally, every call, not only when a purge actually happened — a checkpoint that only fires when something was purged would turn checkpoint timing itself into the exact kind of differential signal this exists to remove."* `purgeUnreadableGroups` in the same release follows that rule; this does not.

**Impact.** Narrow. The migration runs at most once per install, and the config-row write is a louder signal than the checkpoint timing. Recorded because forensic-trace cleanliness is a stated project invariant and this is an inconsistency with a rule cited elsewhere in the same changeset.

**Recommendation.** Move `checkpointStore()` outside the `if moved` branch.

---

## Reviewed and cleared

- **Blob metadata moved off the rotating key** (`AppLayerConfig.blobMetadataKey(from:)`). Deliberate design decision, not an oversight: `sealedBlobSlots` and `layerSequenceNumbers` now derive from the SE Secure Mode key, which never rotates, so no rotation can strand them. HKDF domain separation via a distinct `info` string, matching `LayerStore.deriveKey(from:)`'s pattern. No exposure change — the blob payload those indices point at was already sealed under a key derived from the same root secret, so an index is strictly less sensitive than its target. Recorded so a future reviewer does not mistake it for data escaping the rotation boundary.
- **`purgeUnreadableGroups(using:)`** takes the key as a parameter rather than deriving it internally, which makes "no key, therefore every row looks stranded, therefore delete the table" structurally unrepresentable. Gated to depth 0 so row deletions are never written to the WAL during a coerced session. Checkpoints unconditionally. Clean.
- **`reencryptPreserving` for `deletionToken`.** Correct and load-bearing: the shared `reencrypt(data:)` helper clears unreadable fields to `nil`, and `fetchAllContacts` filters on `deletionToken == nil`. Using the standard helper would have un-deleted every contact soft-deleted before this field was covered. Regression tests present for both directions.
- **`Occulta.entitlements` / `Info.plist`** — removes `aps-environment` (which was set to `development`) and the `remote-notification` background mode. Net attack-surface reduction.
- **`.github/workflows/ci.yml`** — a real blind spot closed. `xcpretty` (last released 2018) parsed this suite, 42 of 44 files being Swift Testing, as **zero tests and zero failures**, and the trailing `|| true` discarded `xcodebuild`'s exit status — so CI reported green regardless of outcome. Now `xcbeautify` with `set -o pipefail` and no `|| true`.
- **`DraftStore.awaitPendingSave()`** — test-only seam, no production caller, no security implication.

---

## Prioritized Remediation Order

| # | Severity | Finding | Status | Effort |
|---|----------|---------|--------|--------|
| 2 | 🟡 MEDIUM | Rotation commits despite skipped re-key passes | Open | One line × 2 sites — **land before merge** |
| 1 | 🔴 HIGH | Stranded `maxBundleVersion` disables signature enforcement | Cause fixed; existing state unfixable | Release note; optional fail-closed hardening |
| 3 | 🔵 LOW | Conditional checkpoint | Open | One line |

---

## Methodology Notes

**Why no sub-agent fan-out.** The `2026-07-24` pass used seven parallel full-file audits, appropriate for a whole-codebase sweep. This was a diff review of a changeset the reviewer had full design context for, including which invariants each change was protecting and why. Cold agents would have re-derived that context at lower fidelity; the review was done inline instead.

**On Finding 1's scope.** It is not introduced by this release and would normally fall outside a diff review. It is included because this release is what surfaced it — the group-eligibility symptom reported by a user (Bug 77) traced back to the same stranded field — and because it silently nullifies a remediation from the previous audit. Excluding it on a scope technicality would have buried the most serious item found.

**On self-review.** Findings 2 and 3 are defects in code written during the same session that produced this release. They are recorded at the severity they warrant rather than softened; Finding 2 in particular reproduces the bug class the release exists to fix, through a path the author added.

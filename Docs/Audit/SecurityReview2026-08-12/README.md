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

**Fix priority:** Findings 2 and 3 are fixed (2026-08-12), tracked as Bugs 78 and 79. Finding 1 is the only one still open, and it needs an operational decision rather than a code fix — its cause is already fixed and its existing damage is unrecoverable — plus an optional fail-closed hardening change.

---

## Findings

### Contacts & Messaging

#### 🔴 HIGH — Stranded `maxBundleVersion` silently disables sender-ephemeral-signature enforcement

- **File:** `Occulta/Services/Contact+Manager.swift:1727` (the enforcement gate), `:1431` (`resolveTargetVersion`, the fail-open fallback)
- **Also implicated:** `Occulta/Data Models/Contact+Model+Reencrypt.swift` (the field's absence from `reencryptAllFields`, fixed in this release), `Occulta/Features/SecureMode/Manager+Security.swift` Step 11 (`deleteSupersededLocalDBArtefacts`)
- **Confidence:** 9/10 — gate, fallback, and capability tier each read directly; the precondition is confirmed present on a real device (the reporting user's install).
- **Status:** ✅ **FIXED 2026-08-12 — Bug 80.** The gate now fails closed on a stranded marker, and the capability tier it reads is a high-water mark so it cannot be lowered by a bundle claiming an old build. The lost version values remain unrecoverable; what that costs is an interop trade, not the bypass. One operational item (how affected users are told) is still open.

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
2. **Hardening:** make the gate fail closed on ambiguity. `resolveTargetVersion` collapses "never seen this contact" (`nil`) and "value present but undecryptable" into the same `.v3fs`, so a *lost* capability marker is indistinguishable from one that never existed. These should be separated, and a lost marker should not silently weaken authentication.

**Update 2026-08-12 — the evidence this depends on is now preserved.** As first written, this release cleared undecryptable values to `nil`, which would have destroyed the distinction on the next rotation of every affected install and made the hardening permanently impossible for exactly the population that has the vulnerability. That conflict was self-inflicted: the clearing existed only to fix the group-eligibility message, and that belongs at the reading site. `maxBundleVersion` now uses the preserving helper and `ContactManager.hasReadableBundleVersion` supplies the three-state answer at all three call sites. The hardening itself is still not applied — failing closed rejects legitimate unsigned bundles from contacts who are genuinely pre-1.10.0 *and* stranded, which is a product decision. But it is now a decision rather than a foreclosed option.

---

### Secure Mode

#### 🟡 MEDIUM — Rotation commits and deletes the old key even when the re-encryption passes were skipped

- **File:** `Occulta/Features/SecureMode/Manager+Security.swift:567` (activation), `:912` (deactivation)
- **Confidence:** 9/10 — control flow read directly; no `else`, no guard, unconditional fall-through to commit.
- **Status:** ✅ **FIXED 2026-08-12** — both sites now guard and throw, with the derivation hoisted ahead of Step 1's PIN check so the abort happens before any row is mutated. The first cut placed the guard where the `if let` had been, which still let `reencryptAllFields` nil every contact's `Data` fields and save them first; see Bug 78 for that correction. Regression coverage drives a nil key through a real activation and deactivation and asserts contacts are untouched.

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
- **Status:** ✅ **FIXED 2026-08-12** — `checkpointStore()` moved outside the conditional. Tracked as Bug 79.

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
| 2 | 🟡 MEDIUM | Rotation commits despite skipped re-key passes | ✅ Fixed 2026-08-12 (Bug 78) | — |
| 1 | 🔴 HIGH | Stranded `maxBundleVersion` disables signature enforcement | ✅ Fixed 2026-08-12 (Bug 80) | Operational note still outstanding |
| 3 | 🔵 LOW | Conditional checkpoint | ✅ Fixed 2026-08-12 (Bug 79) | — |

---

## Methodology Notes

**Why no sub-agent fan-out.** The `2026-07-24` pass used seven parallel full-file audits, appropriate for a whole-codebase sweep. This was a diff review of a changeset the reviewer had full design context for, including which invariants each change was protecting and why. Cold agents would have re-derived that context at lower fidelity; the review was done inline instead.

**On Finding 1's scope.** It is not introduced by this release and would normally fall outside a diff review. It is included because this release is what surfaced it — the group-eligibility symptom reported by a user (Bug 77) traced back to the same stranded field — and because it silently nullifies a remediation from the previous audit. Excluding it on a scope technicality would have buried the most serious item found.

**On self-review.** Findings 2 and 3 are defects in code written during the same session that produced this release. They are recorded at the severity they warrant rather than softened; Finding 2 in particular reproduces the bug class the release exists to fix, through a path the author added.

---

# Second Pass — 2026-08-12, after remediation

Scope: the six commits that fixed the findings above (`9183b8c`…`0607366`). All of that code was
written during the same session, so this pass is a self-review of the fixes rather than of the
release as originally proposed.

## 🔴 Fixed — Secure Enclave round trips moved into a SwiftUI view body

`Group+FormV3.ineligibleHeader` is a computed property consumed from the view body, so SwiftUI
re-evaluates it on every render. The `hasReadableBundleVersion` calls added in `079c2f7` therefore
ran up to `2N` times per render for N ineligible contacts, plus one per row — and `Manager.Crypto`
re-derives the hybrid local DB key on **every** `decrypt` call, with no caching. Before that
change these were `maxBundleVersion == nil`, a pure property read with no crypto at all.

This is the exact cost profile behind Bug 74's `0x8BADF00D` launch watchdog kill, which also
established that backgrounding does not help because the Secure Enclave is a single serial
resource.

**Fixed** by computing the partition once, under one derived key, and storing the
"recorded, readable, and too old" set alongside it. The header is now O(1) and the row label is a
set membership test; neither touches crypto.

## 🟡 Fixed — repeated derivations for the same field

`computeEligibility` cost roughly four derivations per contact: two inside `isVisible(atDepth:)`
and one for each of two complementary `resolveTargetVersion` filters asking the same question
twice. `openGroup`'s gate and `updateMaxVersion` each cost two, both decrypting `maxBundleVersion`
to answer "which tier?" and "was it readable?" separately.

**Fixed** by introducing `ContactManager.BundleVersionState` — `.unrecorded` / `.readable(tier)` /
`.unreadable` — which answers all three questions from one decrypt, with a key-taking variant for
callers classifying many contacts in one pass. `resolveTargetVersion` and
`hasReadableBundleVersion` are now thin wrappers over it, so no call site changed behaviour. The
partition went from ~4N derivations to 1; the gate and the high-water mark from 2 each to 1.

## 🟡 Open — an unrecognised version byte fails open

`resolveTargetVersion` maps a byte that decrypts cleanly but is not a known tier to `.v3fs`
(`byteToVersion(byte) ?? .v3fs`), so the state is `.readable(.v3fs)` — not capable, and the
signature gate accepts an unsigned bundle. Reachable only by running a future build that records a
byte ≥ 0x08 and then returning to 1.10.2; `updateMaxVersion` never writes an unknown byte, so it is
not attacker-controllable. Left as-is because changing the fallback also changes group eligibility
and has existing test coverage asserting the current mapping. "Newer than I understand" should
logically be the most capable case, not the least.

## ⚪ Open — `TestKeyManager` ships in the release binary

`Occulta/Protocols/KeyManagerProtocol.swift` has no `#if DEBUG` anywhere. A fully functional
in-memory key manager that bypasses the Secure Enclave is compiled into the shipped app, and this
release added `simulatesHybridKeyUnavailable` to it — a switch forcing key derivation to return
nil. Not exploitable: reaching it requires code execution, at which point the process is already
lost. Recorded as hygiene. Gating it is not a one-liner, since the SwiftUI previews in
`ContactClassification.swift` and `SecureModeSetupFlow.swift` instantiate it.

## Verified, not changed

The two new pieces of security logic were re-derived against the `Version.known` rank ordering
rather than trusted from their tests: the high-water mark behaves correctly across all five
transitions (never-seen, lower claim, higher claim, stranded + low, stranded + top), and the gate
throws exactly when the sender is known-capable or stranded. The hoisted rotation guards now
precede any staging, blob push or row mutation.

One behavioural note: a key-derivation failure now throws before PIN verification, so error
ordering changed. Not an oracle — the outcome does not vary with the PIN.

## Test flakiness worth watching

`GroupShardGatingTests/mixedGroupSendsToAllWithUniformSlotSize` failed once in four consecutive
full-suite runs, taking 28s in the failing run against 1–2s normally, and passes reliably in
isolation. That profile points at Secure Enclave contention under full-suite load rather than a
logic fault, and the changes in this pass reduce SE work rather than adding it.

It matters more than it used to: until the CI change in this release, `xcpretty` parsed this suite
as zero tests and a trailing `|| true` discarded `xcodebuild`'s exit status, so **no** test failure
could ever fail a build. Now that failures are actually reported, a one-in-four flake will start
failing builds. Worth a dedicated look before that becomes noise people learn to ignore.

# Occulta — Full Codebase Security Review

**Date:** 2026-07-24
**Branch:** `release/v1.10.0`
**Scope:** Every Swift source file under `Occulta/`, `ShareExtension/`, `OccultaPreview/` (production code; test-only files read for intent, not audited as targets; documentation excluded). Not a diff review — includes pre-existing issues, not just recently changed code.
**Method:** Seven parallel full-file audits, one per feature area, cross-checked against the prior `2026-06-10` audit (`Docs/Audit/General/2026-06-10-0900-repo-audit.md`) for regressions/still-open items. Every HIGH and most MEDIUM findings below were independently re-verified by direct source reading (exact file:line tracing of the full exploit chain) before inclusion — see the Confidence field on each finding. Findings below confidence 6 were discarded.

---

## Executive Summary

The crypto core is generally disciplined (fresh AES-GCM nonces everywhere checked, sound HKDF domain separation, a sound hybrid P-256+ML-KEM combiner, a correct Shamir threshold implementation), but this pass found **two HIGH-severity logic bugs that break stated security invariants** the code's own comments and docs promise:

1. ~~**Forward-secrecy prekey lookups ignore which contact they were issued to**, letting any existing contact forge messages that are misattributed to any *other* contact the recipient trusts (`Occulta/Features/Forward+Secrecy/PrekeyManager.swift`).~~ **FIXED 2026-07-26** — see the finding's "Fix applied" note for details.
2. ~~**Cascading out of a nested Secure Mode duress layer permanently un-hides real hidden data and every vault entry**, defeating the "convincing first-duress view" guarantee the duress-layer design is built around (`Occulta/Features/SecureMode/Manager+Security.swift`).~~ **FIXED 2026-07-30** — see the finding's "Fix applied" note for details.

A third HIGH finding, folded in from the prior branch-diff review rather than newly discovered by this pass, is also now fixed:

3. ~~**Draft persistence trusted a stale sensitivity snapshot captured before a 2-second debounce delay**, letting a draft get written to disk moments after a contact was marked sensitive — needing no adversary at all, just ordinary same-device use (`Occulta/UI/Tabs/Contacts/v2/DraftStore.swift`).~~ **FIXED 2026-08-02** — see the finding's "Fix applied" note for details.

All three HIGH findings from this pass are now fixed. Of the three still-open issues from the prior (2026-06-10) audit, the wall-clock PIN lockout bypass (SEC-1) — also HIGH severity — is now fixed as well (2026-08-05); lockout counters lost on key rotation (SEC-2) and `Crypto.sign` leaking error strings as fake signatures (SEC-3, flag-gated off) remain open. One prior issue (release-build peer-key logging) is confirmed fixed.

*Update after a second verification pass:* one originally-listed finding ("broader `AppLayerConfig` rotation gaps") was **retracted** — it turned out to describe a deliberate, documented, fail-safe design choice rather than a bug — and one ("Share Extension session freshness") was **downgraded from MEDIUM to LOW** once it was clear no external attacker can actually reach the affected code path. See the Methodology section at the end for details.

*Update after an objection to finding #1:* an objection was raised that the prekey cross-contact scoping bug is a known, deliberate tradeoff (citing commit `49393d7`, which loosened matching to fix a real `CNContact.identifier`-churn bug on contact re-import). This was investigated and **the finding stands** — the objection's risk argument mischaracterizes the exploit (it doesn't require guessing a UUID; the attacker uses their own legitimate prekey and forges an unauthenticated identity-claim field instead). More importantly, this surfaced that a **pre-existing, committed regression test for this exact bug** (`tempPrekey_wrongContactID_returnsNil`, added 8 days before the loosening commit) was, at review time, being **silently weakened via an uncommitted working-tree change** rather than the underlying bug being fixed — see the addendum under finding #1 below. That uncommitted test change should not be merged as-is.

**Fix priority:** every HIGH-severity finding in this report is now fixed. What remains is the MEDIUM/LOW backlog, in the order listed under [Prioritized Remediation Order](#prioritized-remediation-order).

---

## Findings by Feature

### Forward Secrecy & Post-Quantum

#### ✅ FIXED (was 🔴 HIGH) — Prekey retrieval/consumption ignores contact scoping → cross-contact sender impersonation
- **File:** `Occulta/Features/Forward+Secrecy/PrekeyManager.swift:92-94` (`retrievePrivateKey(for:)`), `:169-205` (`retrieveSecKeysInSE(matching:)`), `:102-104` (`consume(prekey:)`), `:298-353` (`deleteSecKeysInSE`)
- **Also implicated:** `Occulta/Features/Forward+Secrecy/Crypto+Manager+KeyDerivation.swift:76-92` (`deriveInboundKey`, `.forwardSecret`/`.forwardSecretNoPQ` case), `Occulta/Features/Forward+Secrecy/Contact+Model+Profile.swift:199-205` (`isLikelySender`), `Occulta/Features/Forward+Secrecy/Crypto+Manager+ForwardSecrecy.swift:39-67` (`seal`)
- **Confidence:** 9/10 — full exploit chain independently traced end-to-end through the actual code, not just the audit agent's description.
- **Description:** SE prekey tags are documented as `"prekey.<contactID>.<uuid>"` specifically "so that Alice's prekey pools for Bob and Jake are completely isolated — no cross-contact consumption is possible" (`Prekey.swift:10-14`). In practice, `retrievePrivateKey(for:)` calls `retrieveSecKeysInSE(matching: prekey.id)` — the bare UUID only — and the underlying Keychain query filters with `tagString.hasSuffix(substring)` (`PrekeyManager.swift:194`), never checking the `contactID` prefix. `consume(prekey:)` has the identical bug via `deleteSecKeysInSE(matchingTagSubstring:)` (`:325`). `deriveInboundKey` builds `Prekey(id: prekeyID, contactID: senderContactID, publicKey: Data())` (`Crypto+Manager+KeyDerivation.swift:81`) — `senderContactID` here comes from whichever contact `identifyOwner` *believes* sent the bundle — and passes that struct straight into `retrievePrivateKey`, which silently discards the `contactID` field.
  Compounding this: the "sender" is determined by `isLikelySender`, which checks `SHA256(candidateContactPublicKey ‖ fingerprintNonce) == senderFingerprint` (`Contact+Model+Profile.swift:202-204`) — both `fingerprintNonce` and `senderFingerprint` are attacker-chosen cleartext fields the sender fully controls when building the bundle (`Crypto+Manager+ForwardSecrecy.swift:48-49`; documented as "routing only, not in AAD" in `OccultaBundle.swift:57`). Computing a hash match against a *third party's* known public key requires no secret — any contact who knows another contact's public key (trivial between mutual contacts) can forge this field.
- **Exploit scenario:** Bob is a real, legitimately-verified contact of Alice and holds a genuine prekey `(uuid1, pubkey1)` Alice issued to him. Bob also knows Carol's real long-term public key (mutual contact). Bob crafts a bundle by hand: generates his own ephemeral P-256 key, sets `secrecy.prekeyID = uuid1`, `secrecy.mode = .forwardSecretNoPQ` (sidesteps any PQ cross-check — `effectiveQM` is forced `nil` for NoPQ modes), computes `senderFingerprint = SHA256(CarolsRealPubKey ‖ hisOwnChosenNonce)`, and derives the session key himself via `ECDH(hisEphemeralPriv, pubkey1)` — which he can do because he legitimately received `pubkey1`. On Alice's device: `identifyOwner` matches the forged fingerprint to "Carol". `deriveInboundKey` builds `Prekey(id: uuid1, contactID: "Carol", ...)` and looks it up — the suffix-only match finds Alice's real SE key (tagged for Bob, not Carol) anyway, ECDH succeeds (same shared secret Bob computed), the AES-GCM tag verifies, and `decryptSealed` returns `(decodedPayload, sender.identifier)` = Carol's identifier (`Contact+Manager.swift:1516`). The message is now stored/displayed in the app as an authenticated message from Carol, fully authored by Bob — a complete sender-impersonation / message-forgery primitive requiring only being an existing contact of the victim.
- **Recommendation:** In `retrievePrivateKey(for:)` and `consume(prekey:)`, match on the full tag (`Prekey.seTag(for: prekey.id, contactID: prekey.contactID)`) or at minimum verify the retrieved key's stored `contactID` prefix equals `prekey.contactID` before returning it. Independently, consider adding a real sender-binding MAC (like the group path's `senderProof`, keyed off something the sender can't forge without knowing the derived session key *and* the claimed sender's private key) to the single-recipient forward-secret path, since the cleartext fingerprint alone was never meant to be an authentication mechanism.

##### Addendum — an objection was raised against this finding, and it was investigated; the finding stands

After this report was first drafted, a counter-argument was raised that the suffix-only matching is a *deliberate, already-accepted* tradeoff, not a bug: commit `49393d7` ("Deleting tag based on key ID, not the composite tag which can fail if our contact ID changes on deletion and new import.", **Apr 7 2026**) intentionally moved away from exact-tag matching because `Contact.Profile.identifier` for imported contacts is set directly from `CNContact.identifier` (`Contact+Manager.swift:95`), which Apple does not guarantee is stable across a contact delete/re-import or iCloud re-sync — a real, documented operational failure mode, not a hypothetical one. The argument concluded that isolation is "already provided almost entirely by UUID entropy," so an attacker would need to already know another contact's exact prekey UUID — which isn't brute-forceable and isn't disclosed to anyone but the intended recipient — making the practical exploitability of the gap very low, and recommended leaving the loose matching in place.

**This was checked directly and does not hold up, for two separate reasons:**

1. **The risk argument mischaracterizes the exploit.** The "UUID entropy" defense assumes the attacker has to *guess* another contact's prekey UUID. That is not what the exploit in this finding requires. Bob (the attacker) never needs to know Carol's UUID at all — he uses **his own, legitimately-issued** prekey (`uuid1`, which Alice genuinely sent him as part of the normal prekey-sync protocol) and simply *lies about his identity* via the forgeable, unauthenticated `senderFingerprint`/`fingerprintNonce` cleartext fields (confirmed unauthenticated by direct read of `Contact+Model+Profile.swift:199-205` and `Crypto+Manager+ForwardSecrecy.swift:48-49` — computing a match requires only Carol's public key, not a secret). This is a confused-deputy attack using a credential the attacker already legitimately holds, not a brute-force/guessing attack — UUID entropy is irrelevant to it, because nothing is being guessed.

2. **A pre-existing, committed regression test for exactly this bug already exists on this branch, and was about to be silently weakened rather than the bug fixed.** Commit `68ee68c` ("Updating tests.", **Mar 30 2026** — 8 days *before* `49393d7`, and still the current committed state of this file on `release/v1.10.0`) added `tempPrekey_wrongContactID_returnsNil` to `OccultaTests/Forward+Secrecy/ForwardSecrecyIntegrationTests.swift:263`, asserting `pm.retrievePrivateKey(for: injected) == nil` with the comment *"Verifies contactID scoping prevents cross-contact injection."* The Apr 7 commit that loosened the production matching never touched this test — meaning, as of committed HEAD, this test should currently fail against production code (consistent with the prior 2026-06-10 audit's #1 flagged risk, "no CI of any kind," which would explain how this went unnoticed for months). At the time this counter-argument was raised, an **uncommitted** working-tree change to that same test file existed (visible in `git status` throughout this review) that renamed the test to `tempPrekey_wrongContactID_stillResolvesByUUID`, flipped its assertion to `!= nil`, and added a new comment retroactively documenting the loose behavior as "intentional." That is materially different from "this was already a settled, tested design decision" — it reads as the test being edited to match the vulnerable code, not the reverse. **This working-tree change should not be merged as-is** regardless of how the underlying design question is resolved; it silently deletes the only regression coverage for this exact vulnerability class.

**Recommended path (supersedes the single-line recommendation above):** don't just revert to exact-tag matching (reopens the real `CNContact.identifier`-churn bug the Apr 7 commit was fixing) and don't keep suffix-only matching with the test weakened (leaves the vulnerability in place). Instead, decouple SE-tag scoping from Apple's volatile `CNContact.identifier` entirely: use a stable, Occulta-owned identifier for the `contactID` component of the tag — the codebase already generates exactly this kind of stable app-internal UUID for natively-created contacts (see the separate LOW finding on identifier-encryption inconsistency, Contacts & Messaging section) — and re-tag/migrate a contact's prekeys if a re-import/merge is ever detected. This fixes the churn problem the April 7 commit was solving *and* restores real cross-contact isolation, rather than trading one for the other. Restore (or keep) `tempPrekey_wrongContactID_returnsNil` as a real, passing assertion once the fix lands.

##### Fix applied — 2026-07-26

Went with **Option A** (revert to strict exact-tag matching) rather than the stable-ID decoupling above, after tracing the actual data lifecycle: `Contact.Profile.identifier` is set exactly once at creation (`createContacts(from:)` for imports, `save(contact:...)` for native contacts) and is never mutated afterward anywhere in the codebase, and re-importing a churned contact creates an entirely new `Contact.Profile` row rather than updating the existing one in place — so the specific failure mode Option B was designed to guard against (an existing contact's prekeys being orphaned because their `contactID` changed under them) could not be reproduced in the current data model. Given that, the lower-risk, no-migration fix was preferred; this can be revisited if a concrete repro of the original churn bug turns up.

- `retrievePrivateKey(for:)` now matches the full `"prekey.<contactID>.<uuid>"` tag via the pre-existing exact-match `retrieveKey(tag:)` helper (which was never removed, just unused since the Apr 7 commit), instead of `retrieveSecKeysInSE(matching:)`'s bare-UUID suffix match.
- `consume(prekey:)` now performs an exact-tag `SecItemDelete`, keeping its `-> Int` return type (1 = deleted, 0 = not found) since an existing test (`consume_isIdempotent`) asserts on that exact contract.
- `retrieveSecKeysInSE(matching:)` and `deleteSecKeysInSE(matchingTagSubstring:)` — the two substring-matching helpers introduced by the Apr 7 commit — are deleted; they became fully orphaned by this change (verified via repo-wide grep before removal).
- The **uncommitted working-tree change** that had weakened `tempPrekey_wrongContactID_returnsNil` (flagged above) was reverted via `git restore`, restoring the original strict assertion.
- Separately implemented the missing `Manager.PrekeyManager().deleteAllKeys(for: identifier)` call in `Contact+Manager.swift`'s `deleteContact(identifier:)` — this function was documented ("called when a contact is removed from the app") but had **zero call sites** anywhere in production code, meaning a contact's outstanding SE prekeys were never cleaned up on deletion, independent of the scoping bug above. The panic-wipe path (`Manager.App.eraseAllData()`) already called the global `deleteAllKeys()` and needed no change.

**Verification:** build succeeds; `PoolIsolationTests`, `PrekeyManagerRetrievalTests`, `PrekeyManagerConsumptionTests`, and `PrekeyManagerDeletionTests` all pass, including `tempPrekey_wrongContactID_returnsNil` — which now genuinely passes against production code for the first time. One unrelated test (`ExhaustionScenarioTests/exhaustion_afterDrainingAllKeys_nextEncryptProducesFallback`, a PQ-mode-selection assertion) fails both with and without this fix (confirmed via `git stash` comparison against baseline) — pre-existing, not a regression from this change.

#### 🟡 MEDIUM — Single-recipient forward-secret bundles have no sender-identity binding
- **File:** `Occulta/Features/Forward+Secrecy/Crypto+Manager+ForwardSecrecy.swift:39-67` (`seal`, never populates a proof binding sender identity), `Occulta/Services/Contact+Manager.swift:1431-1511` (`decryptSealed`, never checks one)
- **Confidence:** 6/10 — real, confirmed gap; reported separately because it's the structural reason the finding above is exploitable, and would remain a defense-in-depth gap even after that bug is fixed.
- **Description:** Unlike the group-message path, which verifies `senderProof = HMAC(sessionKey, senderLongTermPub)` against the identified sender's actual stored key (`Contact+Manager.swift:1673-1680`, `Crypto+Manager+GroupEncrypt.swift:126,164`), the `.forwardSecret`/`.forwardSecretNoPQ` single-recipient path derives its session key purely from `ECDH(senderEphemeral, recipientPrekey)` — a value that never involves the sender's long-term identity key at all. Successfully opening the AEAD only proves "whoever built this knew a valid `(prekeyID, prekeyPub)` pair," not who sent it.
- **Recommendation:** Add an equivalent identity-binding check (HMAC or signature over the sender's long-term public key, keyed by the derived session key) to the single-recipient forward-secret path, matching the group path's existing pattern.

#### ✅ Reviewed, no issue: nonce freshness, HKDF domain separation, hybrid combiner soundness, ephemeral key discard, one-time prekey consumption ordering, downgrade/version-tamper resistance (all AAD-bound, unknown values rejected not silently accepted).

---

### Secure Mode / Duress

#### ✅ FIXED (was 🔴 HIGH) — Cascade deactivation of a nested duress layer un-hides shallower-hidden contacts and *all* vault entries
- **File:** `Occulta/Features/SecureMode/Manager+Security.swift:690-697` (Step 4, contacts), `:717-726` (Step 6, vault entries), inside `deactivateSecureMode` (function starts `:611`)
- **Confidence:** 8/10 — independently traced against `activateSecureMode` (`:390-498`) to confirm both how `visibleThroughDepth` is set on activation and that nothing re-derives it after Step 4/6 for layers other than the one blob being restored.
- **Description:** `deactivateSecureMode` supports two cases: a full deactivation (`depth ≤ 1`, Secure Mode goes fully off) and a **cascade** deactivation (`depth ≥ 2`, removing one nested "expendable" duress layer while landing back at depth 1 — an intentional, carefully-commented feature: *"shallower blobs remain intact"*, `:775`). But Step 4 unconditionally loops over **every** `Contact.Profile` via `fetchAllContacts()` (no depth filter) and sets `profile.visibleThroughDepth = nil` — which the visibility check (`:1202`, `guard let data = contact.visibleThroughDepth else { return true }`) treats as "visible at every depth." Step 6 does the identical unconditional reset for **every** `VaultEntry` (`:720-723`) — and vault entries have **no blob backup at all** ("Vault entries are not included in the blob," `:453`), so there is no restore mechanism for them under any circumstance.
  Step 5 only restores content + `visibleThroughDepth` for contacts recorded in the *specific* blob being removed (`blobDepth = depth - 1`, `:649,709-712`). A contact hidden at a **shallower** depth (e.g. depth 0 — the real user's actual data, hidden since the very first activation) lives in a *different* blob (`blobDepth = 0`) that this cascade call never touches. Since its real, decrypted text content is continuously carried forward through every key rotation (`reencryptAllFields`, `:475-478` during activation, `:691` during deactivation — it's never left undecryptable), and Step 4 just cleared its visibility gate to "always visible," it becomes fully visible the moment the app lands at depth 1.
- **Exploit scenario:** The real user activates Secure Mode (depth 0→1) with genuinely sensitive contacts and vault entries hidden at depth 0. Later — from within the depth-1 duress view, e.g. under actual coercion — a second, nested Secure Mode layer is activated (depth 1→2; supported by `activateSecureMode`'s depth-based branching). When that depth-2 layer is deactivated (cascading back to depth 1), every depth-0-hidden contact and **every vault entry regardless of its configured depth** becomes visible in the depth-1 view — exactly the view meant to stay a convincing, clean duress presentation for a coercer. `OccultaTests/SecureMode/` has no test exercising `currentDepth ≥ 2` activate/deactivate, so this path is unverified by CI.
- **Recommendation:** Scope Step 4/6's `visibleThroughDepth = nil` reset to `depth ≤ 1` only (full deactivation). For cascade deactivation (`depth ≥ 2`), leave contacts/entries whose stored depth is shallower than `blobDepth` untouched, and restore only the depth being removed. Vault entries need an actual restore path for the cascade case since they currently have none.

##### Fix applied — 2026-07-30

Implemented a simpler rule than the recommendation above, arrived at during planning: rather than adding a `blobDepth` comparison to Step 4/6 and a new restore mechanism for vault entries, both steps now **always preserve each item's real classification depth**, re-encrypting it verbatim under the staged key instead of resetting it:

- Decode the item's current depth before touching anything else (contacts default to `Int.max` on decode failure, vault entries to `0` — each keeping its own pre-existing fallback convention).
- If the decoded depth **is** `Int.max` (genuinely never classified) → write literal `nil`, preserving the existing forensic-neutrality convention (indistinguishable from an item that never went through Secure Mode).
- Any other, genuinely finite depth → re-encrypted verbatim under the staged key. Never manufacture `nil` for a value that was genuinely finite.

This fixes the reported shallow-depth exposure (both for contacts and vault entries), and additionally fixes a second, related bug found during planning that the original recommendation's `blobDepth`-conditional approach would **not** have caught: a contact/entry classified *deeper* than the layer being removed (e.g. "hide once beyond depth 2") was also being permanently flattened to "never hide" by an unrelated, shallower cascade — the same root cause in the other direction. Vault entries needed no separate restore mechanism once Step 6 stopped clobbering them, since they were never removed from the DB in the first place — there was nothing to restore, only something to stop destroying.

`activateSecureMode` was checked and needed no equivalent fix — its own classification logic already preserved depths correctly; only `deactivateSecureMode` had the blanket-reset bug.

**Test coverage** (`OccultaTests/SecureMode/SecureModeActivationTests.swift`, `CascadeDeactivationDepthTests` suite — written red first, confirmed failing against the unfixed code, then made to pass):
- `depthZeroContact_staysHiddenAfterCascadeDeactivation` — the exact reported scenario (depth-0 secret exposed by a 2→1 cascade).
- `depthZeroVaultEntry_staysHiddenAfterCascadeDeactivation` — same scenario for vault entries, which have no blob/restore path at all.
- `deeperClassification_survivesUnrelatedShallowerCascade` — the additional bug found during planning (a deeper classification erased by an unrelated shallower cascade).
- `neverClassifiedContact_remainsLiteralNilAfterCascadeDeactivation` — forensic-neutrality check: an unclassified contact must come back as literal `nil`, not an explicit encrypted `Int.max`.
- `blobBoundaryContact_stillRestoredCorrectlyDuringCascade` — confirms a contact classified at *exactly* the depth being removed is still correctly restored via Step 5's blob-restore path, i.e. this fix doesn't interfere with the existing restore mechanism it sits alongside.

**Verification:** full `OccultaTests` target run after the fix — 0 failures.

#### ✅ FIXED (was 🔴 HIGH) — PIN lockout is wall-clock based and bypassable by changing the device clock *(from 2026-06-10 audit — SEC-1)*
- **File:** `Occulta/Features/SecureMode/Manager+Security.swift:851` (`Date.now < expiry` inside `verify(_:)`), `:882` (`Date.now.addingTimeInterval(delay)`)
- **Confidence:** 9/10 — re-verified against current line numbers.
- **Description:** The escalating lockout after repeated wrong PIN attempts (up to 24h) is enforced purely by comparing `Date.now` to a stored expiry. Since SE-bound PIN verifiers already prevent offline brute force, this wall-clock check is the *only* throttle against an online (on-device) brute force. An adversary holding the unlocked device — the exact coercion scenario Secure Mode exists to resist — can open Settings and roll the system clock forward to instantly clear any lockout, then keep guessing (a 6-digit PIN is a 10⁶ keyspace; automated input via accessibility/HID scripting makes exhaustive search plausible over a period of days without this throttle).
- **Recommendation:** Back the lockout with a monotonic, non-user-adjustable clock source (e.g. `ProcessInfo.systemUptime` combined with a persisted boot-count/anti-rollback counter, or a Secure Enclave–backed counter) instead of wall-clock `Date`.

##### Fix applied — 2026-08-05

Implemented via `ProcessInfo.systemUptime` rather than a Secure-Enclave-backed counter — Apple doesn't expose a general-purpose tamper-evident counter to third-party apps via CryptoKit/Security.framework, so that half of the original recommendation wasn't actually implementable as stated. `verify(_:)`'s gate now compares a stored **uptime anchor** against current `systemUptime` instead of a wall-clock `Date`:

- Settings → Date & Time changes have zero effect on `systemUptime`, so there's nothing left for that attack to bypass.
- The only way uptime can move backward is an actual reboot, detected explicitly (`currentUptime < anchor`) and re-anchored rather than credited as elapsed time — a reboot re-starts the same required wait from a fresh anchor rather than clearing it for free.

An injectable `LockoutClock` protocol was added (`Manager+Security.swift`), with `SystemLockoutClock` as the real implementation wired in via a default init parameter — no existing call site needed to change. `AppLayerConfig`'s `lockoutExpiryEncrypted` (a `Date`) was replaced by `lockoutAnchorUptimeEncrypted` (a `TimeInterval`); `lockoutExpiry()` (the `PINEntry` countdown display) now computes an estimated wall-clock date from the same uptime math, purely for display, never fed back into the actual gate.

Simpler than first sketched: only one new field was needed, not three — the required delay is always re-derivable from the already-persisted `lockoutCount` via the existing `lockoutDelay(for:)` schedule, and a separate wall-clock tamper-detection field turned out to be redundant once the comparison is uptime-only, since uptime is already immune to clock changes by construction.

**Test coverage** (`OccultaTests/SecureMode/LockoutAntiRollbackTests.swift`, new): a `FakeLockoutClock` with independently-settable `now`/`systemUptime` reproduces both attacks directly — rolling the clock forward, and simulating a reboot — plus control cases confirming genuine elapsed uptime still clears the lockout normally and a reboot delays rather than permanently locks. Verified meaningful by temporarily swapping the uptime source back to wall-clock-derived seconds (reintroducing the original bug) and confirming the core tests went red, then reverting. All existing `LockoutCounterTests` pass unchanged.

**Verification:** full `OccultaTests` target, 639/639, twice in a row.

#### 🟡 MEDIUM — Lockout counters silently reset on decode failure and aren't carried through key rotation *(still present — SEC-2)*
- **File:** `Occulta/Features/SecureMode/AppLayerConfig+Model.swift:394-400` (`readLockoutCount()` → 0 on any failure), `:406-412` (`readLockoutAnchorUptime()` → nil on any failure — renamed from `readLockoutExpiry()` by the SEC-1 fix above, same underlying gap)
- **Confidence:** 8/10 — re-verified; root cause confirmed as the canonical local-DB key rotation loop never touching these two fields.
- **Description:** `lockoutCountEncrypted`/`lockoutAnchorUptimeEncrypted` are encrypted under the same canonical local-DB key that gets staged/rotated/deleted during Secure Mode activation/deactivation, but neither field appears anywhere in the rotation sequence. Once the old key is deleted, any in-progress lockout becomes permanently undecryptable and silently reads back as "no lockout" — not compounding SEC-1 anymore since that gate is no longer wall-clock-based, but still a real, independent gap: any single-field DB read hiccup, or a Secure Mode activation/deactivation mid-lockout, silently resets the brute-force counter.
- **Recommendation:** Include these two fields in the same re-encryption pass that already runs for contacts/vault entries during activation/deactivation.

#### 🟡 MEDIUM — WAL checkpoint runs before the group-membership purge it's supposed to cover
- **File:** `Occulta/Services/ContactManager+Classification.swift:65-68` (`saveClassification`), `:91-94` (`setVisibility`) — same pattern also in `Occulta/Services/Contact+Manager.swift`'s `delete`
- **Confidence:** 7/10 — call order confirmed directly by reading the current file; the downstream `Group.purgeMembersFromDuressDepths`/`reencryptAllDepths` save does happen after the checkpoint with no follow-up flush.
- **Description:** All three sites call `modelContext.save()` → `security.checkpointStore()` → *then* `cleanUpGroupDuressMembership(...)`, which performs its own, separate `modelContext.save()` for the actual group re-encryption. `checkpointStore()`'s own doc comment states its purpose is to make `PRAGMA secure_delete=ON` zero the freed page for a purge-adjacent write immediately, rather than leaving it to whatever unrelated checkpoint happens next — but the group-membership write lands in the WAL *after* the checkpoint already ran, so it isn't covered by this call.
- **Recommendation:** Move (or duplicate) the `checkpointStore()` call to after `cleanUpGroupDuressMembership(...)` at all three sites.

#### ❌ RETRACTED (after second-pass verification) — "Several other `AppLayerConfig` fields share SEC-2's root cause"
- **File:** `Occulta/Features/SecureMode/AppLayerConfig+Model.swift:60-91` (field docs for `coercerBaseDepth`), `:319-343` (`readPersistedDepth`, `readPinEnabled`), `Occulta/Features/SecureMode/Manager+Security.swift` (confirmed: `activateSecureMode`/`deactivateSecureMode` never call `writePinEnabled`/`writePersistedDepth`/`writeCoercerBaseDepth`)
- **Original claim:** `persistedDepth`, `pinEnabledPerDepth[*]`, and `coercerBaseDepth` are encrypted under the same rotating canonical key as the lockout fields and are similarly never rewritten during rotation, so a later rotation could make them undecryptable and cause the PIN gate to "silently snap back on."
- **Why this was retracted on re-verification:** the mechanism (rotation not touching these fields) is real — confirmed by grep, no `write*` calls for these fields appear anywhere in the rotation functions. But the *consequence* is not a vulnerability: `AppLayerConfig+Model.swift:81-84` explicitly documents that the developer already reasoned through this exact failure mode: *"On any decode failure the field falls back to 0, which is conservative: it restricts rather than opens... reverts to pre-fix behaviour (the two tells reappear), not to a state that exposes the real user's data."* `pinEnabledPerDepth` falls back to `true` (PIN **required**) — the *more* restrictive direction, not less — and `persistedDepth` falls back to `0`, documented as "the safe default." None of these fallbacks weaken a security boundary or expose hidden data; the worst case is a forensic-consistency/UX regression for the coercer-deniability illusion, not a path to the real user's secrets. Does not meet this review's bar for a vulnerability finding — retracted rather than downgraded, since the original framing ("PIN gate snaps back on" as a bad outcome) was simply backwards.
- **Confidence in retraction:** 8/10 — verified directly against the code's own documented reasoning, not just its runtime behavior.

#### ✅ Reviewed, no issue: duress/decoy PIN routing-alias design; `AppGroupLayerStoreBackend.write()` write-then-delete ordering; no TOCTOU pattern in `PINEntry.swift`'s async delays (they're UI padding after the security decision, not before it).

---

### Contacts & Messaging

#### ✅ FIXED (was 🔴 HIGH) — Draft persistence trusts a stale sensitivity flag captured before a debounce delay
*(Confirmed in the prior branch-diff security review on 2026-07-25; reproduced here for completeness since it's part of the full codebase.)*
- **File:** `Occulta/UI/Tabs/Contacts/v2/DraftStore.swift:27-46` (`scheduleSave`), consumed from `ContactDetailV2.swift:178-186` and identically in `v3/ContactDetailV3.swift`
- **Confidence:** 8/10.
- **Description:** `scheduleDraftSave()` evaluates `composeVM.isSensitive(contactManager:)` once, at keystroke time, and captures that `Bool` into a `Task` that sleeps 2 seconds before calling `save()`. `save()`'s only sensitivity gate (`guard !isSensitive else { return }`) trusts that stale value and never re-checks the contact's live classification at write time. Marking a contact sensitive via Trust Check within that 2-second window doesn't cancel the pending task, so the draft gets written to disk moments after the purge that was meant to remove it — defeating the documented "Option E: no draft is ever written for a sensitive contact" invariant.
- **Recommendation:** Re-evaluate `isSensitive` fresh (fetched from `ContactManager`) inside the `Task`, immediately before calling `save()`, rather than capturing it at schedule time.

##### Fix applied — 2026-08-02

`scheduleSave`'s `isSensitive` parameter changed from a `Bool` to `@escaping () -> Bool`, called once inside the debounced `Task`, immediately before `save()` — after the delay, not before. Updated at all three call sites (`ContactDetailV2.swift`, `ContactDetailV3.swift`, and a third site not originally listed, `GroupDetailV3.swift`, which shares the identical pattern): each now extracts `composeVM`/`contactManager` as local references and passes a closure over them instead of a pre-computed snapshot. `flush()` (used by `.onDisappear`/backgrounding) was left unchanged — it saves synchronously with no delay, so it was never stale.

This also turned out to be a performance win, not just a correctness fix: `scheduleDraftSave()` fires on every keystroke, and `isSensitive` does a real DB fetch plus a Secure Enclave decrypt with no caching. Under the old design every keystroke paid that cost even though only the last one before the debounce window closes ever mattered — the fix cuts it from once per keystroke to once per debounce window that actually completes.

Confirmed via the Trust Check interaction specifically raised during planning: since both `ContactManager.setVisibility` and the post-delay body of `save()` are synchronous with no internal suspension points, and `isSensitive` re-fetches live state on every call with no caching, a sensitivity change made mid-debounce is correctly observed at write time. The only remaining theoretical gap is an ordering coincidence between the Task's wake-from-sleep and a button tap landing in the exact same run-loop tick — not reachable through ordinary user interaction, and not worth formal locking to close.

**Test coverage** (`OccultaTests/Contacts/DraftStoreTests.swift`, new): `staleSensitivity_doesNotWriteWhenMarkedSensitiveDuringDebounce` reproduces the exact reported race directly against `DraftStore`; two control tests confirm the fix isn't just a no-op; `isSensitiveClosure_evaluatedOnlyOnce_acrossARapidKeystrokeBurst` confirms the performance improvement. Verified meaningful by temporarily reintroducing eager evaluation (same signature, old timing) and confirming exactly the two relevant tests went red while the controls stayed green.

**Verification:** full `OccultaTests` target, 633/633, twice in a row (a first pass surfaced a real Secure-Enclave-contention timing flake under full-suite parallel load, unrelated to the fix itself, resolved by polling with a generous timeout instead of a fixed sleep).

#### 🟢 LOW — Contact identifier is encrypted for imported contacts but stored in plaintext for locally-created ones
- **File:** `Occulta/Services/Contact+Manager.swift:95` (`createContacts(from:)` — encrypts `identifier`) vs. `:230` (`save(contact:currentDepth:using:)` — `let encryptedIdentifier = contact.identifier`, stored verbatim); root cause in `Occulta/UI/Tabs/Contacts/v2/ContactFormV2.swift:36` (`.create` mode seeds a raw `UUID().uuidString`)
- **Confidence:** 7/10.
- **Description:** Every other field on the same `save(contact:...)` call path is encrypted; `identifier` alone is stored as a raw UUID string for contacts created natively in Occulta, while contacts imported from the system Contacts app get an AES-encrypted+base64 blob in the same column. Anyone with raw filesystem/backup access can distinguish "manually entered" from "imported" contacts purely from the identifier column's format, with no decryption needed — a structural forensic tell the project's other code goes out of its way to avoid (per its own "forensic trace clean" bar).
- **Recommendation:** Encrypt `identifier` in the `save(contact:...)` path the same way `createContacts` does.

#### ✅ Reviewed, no issue: no other stale-capture-before-async-gap pattern found beyond DraftStore; `deleteContact`/`setVisibility`/`saveClassification` purge coverage is consistent across contact-keyed data types (aside from the separately-tracked shard-custody gap, see Vault section below); no cross-contact leakage in SwiftData predicates; attachment filenames in the **compose/outbound** path are always locally sourced, no traversal risk there (see App Core section for the **inbound** path, which is a different, real issue).

---

### App Core, Key Management & Services

#### 🟡 MEDIUM — Path traversal via attacker-controlled attachment filename on the inbound message path
- **File:** `Occulta/App/OccultaApp.swift:638-641`
- **Confidence:** 8/10 — independently verified: `Occulta.File.Metadata.init(from:)` (`Occulta/Data Models/Transfers.swift:59-64`) decodes `name` verbatim from the wire payload with zero sanitization, and this `metadata` genuinely originates from the decrypted, sender-controlled `Basket`.
  ```swift
  let fileURL = tempDir
      .appendingPathComponent(metadata.name ?? UUID().uuidString)
      .appendingPathExtension(metadata.extension ?? "bin")
  ```
- **Description:** `metadata.name` is attacker-controlled content — chosen by whoever built the inbound `.occ` bundle (a contact's app, or a modified/malicious client after key exchange), decoded with no path-separator stripping. `URL.appendingPathComponent` does not collapse `..` segments before the resulting path is used for file I/O, so a crafted name like `"../Library/Application Support/default.store"` can steer the write outside `tempDir` to a deterministic, guessable sandbox path — one `..` is enough to reach `Library/` as a sibling of `tmp/`. Combined with fully attacker-controlled file *content* (the decrypted attachment bytes), this is a path + content write primitive within the app sandbox. Concretely, overwriting the SwiftData store file corrupts it and causes `ModelContainer` creation to `fatalError` on next launch (`OccultaApp.swift:58-62`) — targeted, persistent data corruption from a single crafted incoming message, not just a crash. Only the *outbound* share-extension path already generates safe randomized names (`UUID().uuidString`); that discipline isn't applied here.
- **Recommendation:** Ignore the peer-supplied `name` for path construction — always use a generated UUID, keeping only the (still-should-be-sanitized) extension from `metadata.extension`.

#### 🟡 MEDIUM — `Crypto.sign(data:)` returns human-readable error strings as the signature value itself *(still present — SEC-3)*
- **File:** `Occulta/Services/Crypto+Manager.swift:126-151`, consumed unconditionally at `Occulta/UI/Tabs/Sign/Sign.swift:75-76`
- **Confidence:** 9/10 — re-verified current line numbers and the flag gate.
- **Description:** On failure, `sign(data:)` returns strings like `"Key or data is missing"` or `"Signature could not be created, try again."` as its `String` return value, with no distinguishing error type. `Sign.swift` uppercases and embeds this directly into `"MavSig: \(signature)"`, which the user could copy and publish believing it's a real signature. Mitigated today only by `features.plist`'s `signature = false`, gating the entire Sign/Verify tab out of the reachable UI — the underlying bug in `Crypto+Manager.swift` is unchanged and would be live the moment that flag flips on.
- **Recommendation:** Change the return type to `Result<String, Error>` (or throw) so success and failure can't be conflated at any call site, independent of the feature flag.

#### 🟢 LOW — Unbounded inbound file read into memory *(still present — SEC-5)*
- **File:** `Occulta/App/OccultaApp.swift:447` (`try await URLSession.shared.data(from: fileLocation)`)
- **Confidence:** 8/10 — re-verified, no size guard added anywhere upstream since the prior audit.
- **Description:** Any inbound `.occ`/`.occbak` file (Files app, AirDrop, share extension) is loaded fully into memory with no size check. A very large file is a crash/OOM, not a data-confidentiality issue — kept here at LOW per this review's DOS-exclusion guidance, but noted since it was already flagged and remains open.
- **Recommendation:** Add a reasonable size cap before the full read, or stream/chunk the read.

#### ✅ Reviewed, no issue: SE key tag inventory has no cross-purpose reuse; `features.plist` flags fail *closed* (default `false`) on a missing/corrupt plist; release-build peer-key logging (prior SEC-4) is now fully `#if DEBUG`-gated — **confirmed fixed**; Passphrase generation uses `SecRandomCopyBytes` (CSPRNG) throughout; QR generator doesn't over-encode key material; Onboarding does no key/passphrase display or transmission.

---

### Identity Challenge & Key Exchange

#### 🟡 MEDIUM — Peer-identity pinning ("MITM guard") is only applied to one of three MultipeerConnectivity exchange phases
- **File:** `Occulta/Services/Exchange+Manager.swift:389-422` (Discovery phase, no peer check), `:426-432` (Identity phase — has the check, explicitly commented "MITM guard"), `:540-598` (Ciphertext phase, no peer check); session/advertiser setup around `:724` (`browser(_:foundPeer:...)`, auto-invites) and `:740` (`advertiser(_:didReceiveInvitationFromPeer:...)`, unconditionally accepts)
- **Confidence:** 8/10 — independently re-traced line-by-line on second pass (up from 7/10): confirmed `handleReceivedData`'s Discovery handler (`:389-422`) has no peer check at all, the Ciphertext handler (`:540-598`) gates only on `exchangeStatus` shape and genuinely nils out `self.privateKeyHandle` (the one-shot SE key) on the first structurally-valid ciphertext regardless of sender, and `advertiser(_:didReceiveInvitationFromPeer:...)` (`:744`) unconditionally calls `invitationHandler(true, self.multipeerSession)` with no allow-list or peer cap anywhere in the session setup.
- **Description:** `handleReceivedData` validates `peerID == connectedPeerID` only for `.isIdentity` messages. Because the session has no peer cap and both the browser and advertiser auto-accept, a second peer can join the same `MCSession` mid-exchange. Since the Discovery and Ciphertext phase handlers never check `peerID`, an attacker within Bluetooth/MC range (not necessarily within the 25cm UWB proximity gate) can inject a ciphertext message that gets processed as if from the legitimate, already-identity-verified peer — consuming/poisoning the one-shot ML-KEM exchange before the real peer's message arrives. The classical P-256 identity stays correctly bound (so full silent impersonation isn't achieved — a user comparing diceware confirmation words would notice), but the post-quantum half of the exchange can be corrupted/denied from outside the UWB proximity boundary the design relies on.
- **Recommendation:** Apply the same `peerID == connectedPeerID` check to the Discovery and Ciphertext phase handlers, not just Identity.

#### ✅ Reviewed, no issue: UWB proximity gate (≤0.25m) is enforced from real NearbyInteraction ranging, not a peer-supplied claim; identity-challenge nonces are single-use on every exit path (pass, fail, stale, bad-signature) with a real replay window; signature domain-separation prefix applied consistently via one shared helper, no bypass path found; no error silently treated as success. Note: this branch currently has **no QR-code key-exchange path implemented** (`NearbyInteraction/`/`QRCode/` subdirectories are empty) — the QR-substitution-attack methodology item in this review's scope doesn't apply to current code.

---

### Share Extension

#### 🟢 LOW (downgraded from MEDIUM after second pass) — No enforced ordering or freshness check between orphan-session sweep and `occulta://share` processing
- **File:** `Occulta/App/OccultaApp.swift:264-271` (cleanup trigger, only on `scenePhase == .active`), `:418-420` (`occulta://share?session=` routes straight to `processShareSession` with no staleness check), `:690-735` (`processShareSession` itself — confirmed no age/`manifest.createdAt` check anywhere in the function); `Occulta/Features/ShareExtension/ContactManager+ShareIndex.swift:118-155` (`cleanupPendingSessions`, has its own 1-hour cutoff, gated on `containerURL(forSecurityApplicationGroupIdentifier:)` for `group.com.occulta.shared`)
- **Confidence:** 6/10 — the ordering/staleness gap itself is confirmed real on re-reading all three functions in full. Severity downgraded from the original MEDIUM: re-verification confirms `pending/<uuid>/` only exists inside the `group.com.occulta.shared` App Group container, which **only Occulta's own main app and its own Share Extension can write to** — no external/third-party app, despite being able to invoke the globally-registered `occulta://` URL scheme with an arbitrary guessed UUID, has any way to seed a session directory for that UUID to begin with. A guessed/malicious invocation from another app hits a nonexistent directory and no-ops (caught by the surrounding `do/catch`). The realistic residual risk is narrower than originally framed: a legitimate but stale/already-processed session belonging to this app being unexpectedly reprocessed (e.g. a re-tapped notification or duplicate deep-link delivery) — a correctness/idempotency concern, not a cross-app data-exposure path.
- **Recommendation:** Apply the same staleness cutoff `cleanupPendingSessions` uses inside `processShareSession` itself, for correctness/robustness rather than as a security fix.

#### 🟢 LOW — Decrypted attachment plaintext isn't zeroed on the error/throw path
- **File:** `Occulta/App/OccultaApp.swift:713-773` (`processShareSession`)
- **Confidence:** 7/10.
- **Description:** Ciphertext buffers are correctly zeroed immediately after each decrypt, and plaintext is zeroed in the success-path loop (`:752-754`) — but the `catch` block (`:768-773`) only deletes the session directory; it never touches the in-memory `files` array, so on any failure after decryption, plaintext attachment bytes are left un-zeroed on the heap until ARC happens to deallocate them. Inconsistent with the function's own zeroing discipline elsewhere.
- **Recommendation:** Zero the `files` array's content in the `catch` block too, not just on the success path.

#### ✅ Reviewed, no issue: extension writes only to its designated `pending/<sessionID>/` subdirectory with internally-generated filenames (no traversal vector); deep link carries only a UUID; ciphertext is never logged/cached; session directories are cleaned up on both success and failure; `OccultaPreview` never touches decrypted content, so no QuickLook plaintext-cache exposure.

---

### Vault & Shard Custody

**No qualifying findings.** This is a well-engineered Shamir secret-sharing implementation: `SecRandomCopyBytes`-driven polynomials, correct rejection of duplicate/zero x-coordinates and below-threshold reconstruction (the AES-GCM tag acts as the real integrity backstop even where an explicit threshold check is skipped), ECDSA-verified trustee-side shard operations with no bypass, and no plaintext key/shard material touching disk or logs.

One already-tracked, pre-existing gap (not re-reported as new — see `Docs/Bugs/v1.10.0/Shard-Custody-Not-Cleaned-Up-On-Contact-Deletion.md`): shard-custody records aren't cleaned up on contact deletion or Secure Mode activation. Still open; out of scope for this report only because it already has its own tracking document.

---

## Prioritized Remediation Order

1. ~~**HIGH** — Prekey contact-scoping bug (Forward Secrecy) — bounded fix (tag matching), high impact (message forgery/misattribution).~~ **FIXED 2026-07-26.**
2. ~~**HIGH** — Cascade deactivation exposure (Secure Mode) — bounded fix (scope the visibility reset to full deactivation only), directly undermines the duress feature's core promise.~~ **FIXED 2026-07-30.**
3. ~~**HIGH** — Wall-clock PIN lockout bypass (Secure Mode, open since 2026-06-10) — needs a monotonic/anti-rollback clock source; slightly larger fix but well-understood.~~ **FIXED 2026-08-05.**
4. ~~**HIGH** — DraftStore stale-`isSensitive` race (Contacts & Messaging) — bounded fix (re-check inside the `Task`), and unlike #1-#3 it needs no adversary at all — ordinary same-device usage (type, then hide the contact within 2s) triggers it.~~ **FIXED 2026-08-02.**
5. **MEDIUM** — Path traversal via inbound attachment filename (App Core) — bounded fix (drop peer-supplied name), real data-integrity impact.
6. **MEDIUM** — Peer-identity pinning gap (Identity Challenge/Key Exchange) — bounded fix (extend one existing check to two more phases).
7. **MEDIUM** — Lockout counters lost on key rotation (Secure Mode, still open) — same rotation loop that needs fixing for #2 could absorb this.
8. **MEDIUM** — No sender-identity binding in single-recipient forward-secret path — defense-in-depth for #1, do alongside it.
9. **MEDIUM** — `Crypto.sign` error-string-as-signature (App Core, still open, currently flag-gated off) — low urgency while `signature` flag stays `false`, but fix before ever enabling it.
10. **MEDIUM** — WAL checkpoint ordering around group-membership purge (Secure Mode / Contacts) — forensic hygiene, not a data-breach path.
11. **LOW** — Contact-identifier plaintext inconsistency, unzeroed plaintext on share-extension error path, unbounded inbound file read, share-extension session freshness ordering (all low real-world impact/exploitability, cheap fixes).

---

## Notes on Methodology & Confidence

- Every finding in this report — including all items originally flagged as "single-pass only" — has now been independently re-verified via direct source reading of the full exploit chain, across two passes. The first pass (7 parallel per-feature audits) surfaced candidates; a planned second round of parallel verification agents was interrupted by an API session-usage limit, so the second pass was completed by direct manual code reading instead of spawned agents. All confidence scores above reflect this completed second pass.
- The second pass produced two corrections to the original draft, not just confirmations: the "broader `AppLayerConfig` rotation gaps" finding was **retracted** — the code's own comments show the fallback behavior is a deliberate, documented, fail-safe design choice, not a bug — and the "Share Extension session freshness" finding was **downgraded from MEDIUM to LOW** after confirming no external attacker can actually seed the exploitable state (App Group container access is restricted to Occulta's own app and extension). Everything else was confirmed as originally assessed, with two (the prekey-scoping HIGH and the MPC peer-pinning MEDIUM) gaining higher confidence after the full trace.
- Findings already tracked in existing `Docs/Bugs/` documents are referenced but not duplicated here.
- Denial-of-service, resource-exhaustion, and "missing hardening without a concrete exploit path" issues were explicitly out of scope per this review's own instructions and are not listed, even where noticed in passing.

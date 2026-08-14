# CLAUDE.md

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.
- Group related properties into a single unit.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

## Syntax

- User self. for instance variables.

---

### Reasoning

## Build & Test

A native Xcode project with **one** SPM dependency: `apple/swift-crypto` (pinned 4.2.0, pulling
`apple/swift-asn1`). No CocoaPods or Carthage. Nothing calls it — `import Crypto` appears in one
file, the app builds with that import removed, and ML-KEM comes from CryptoKit — but it still
ships five vendored BoringSSL resource bundles inside the app. Removal is queued; see §7 of
`Docs/Audit/SECURITY_CHECKLIST.md`. Do not describe this project as dependency-free.

- **Open:** `open Occulta.xcodeproj`
- **Build/Run:** Cmd+R in Xcode, targeting a physical iPhone 11+ (U1 chip required for NearbyInteraction)
- **Test all:** Cmd+U in Xcode, or via CLI:

**Requirements:** `IPHONEOS_DEPLOYMENT_TARGET` is **18.6** across all ten build configurations;
Xcode 26.2 / iOS SDK 26.2 at the last release. Physical device needed for NearbyInteraction.

Note the deployment target and the availability gates are different things: ML-KEM is behind
`#available(iOS 26, *)` in `PQProvider`, so the post-quantum path is live only on iOS 26+ and the
classical-only modes exist for everything between 18.6 and that.

**Secure Enclave and the test suite.** Some tests inject `TestKeyManager` and run anywhere; **260
of 738** need a real Enclave, because `Group`'s crypto, `reencryptAllFields` and the prekey store
go through `Manager.Key()` directly with no injection seam. (Measured 2026-08-14 by counting
`@Test` declarations gated directly or by their enclosing suite — re-measure rather than trusting
this number, it has drifted before: it read "roughly 146" while the real figure was 260.) Those carry
`.enabled(if: secureEnclaveAvailable())` and report as **skipped** where one is unavailable —
notably on GitHub-hosted CI runners, which are VMs. A Simulator on bare-metal Apple Silicon does
have Enclave access and runs the full suite.

**A separate and worse problem: ~113 tests still skip the old way** — `print("⚠︎ Skipping"); return`
— which reports as **passed**, not skipped. So the suite's green count overstates what actually
ran, and unlike the gated tests the shortfall is invisible. Prefer injecting a key manager; where
there is no seam, use `.enabled(if: secureEnclaveAvailable())` so the cost stays visible. Do not
add more of the legacy form.

So **a green CI run is not a passing test suite**: it verifies the parts that do not touch key
material. Before tagging a release, run the full suite locally on a host with an Enclave and
confirm the skip count is zero — see the Testing Gate in `Docs/Audit/SECURITY_CHECKLIST.md`. When
adding a test that needs real key material, prefer injecting a key manager over gating it; gate it
only where no seam exists.

## Architecture

Occulta is an offline-first, serverless iOS contact book where physical proximity (UWB/Bluetooth) serves as the key distribution mechanism. All cryptography uses Apple frameworks only (CryptoKit + Security.framework).

Privacy and Security are paramount. There can be no vulnerabilities. Consider all possible attack vectors.

We must be forensic trace clean. We should not be leaving traces that we are hiding something. Alert if you see something.


### Testing

Unit tests for all implementations

### Branches

- `develop` — integration branch; PRs target this
- `release/v*` — release branches
- Feature branches prefixed `v1.*.0/`

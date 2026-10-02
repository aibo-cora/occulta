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

A native Xcode project with **no** third-party dependencies — no remote SPM packages, CocoaPods, or
Carthage. All crypto is CryptoKit and Security.framework, ML-KEM included. Don't add one — in
particular not `apple/swift-crypto`, which on Apple platforms only re-exports CryptoKit but ships
BoringSSL bundles with it; see §7 of `Docs/Audit/SECURITY_CHECKLIST.md`.

The one package is `OccultaCore/`, first-party and in this repo, linked to the app target only. It
holds the code being extracted for reuse (`ShamirSecretSharing`, `PQProvider` so far) and must stay
dependency-free: its `Package.swift` declares none, and adding one is the same supply-chain change
as adding it to the app. It is nonisolated by default, unlike the app's `MainActor`. Its tests stay
in `OccultaTests` (`@testable import OccultaCore`) so the one test command below still runs them.

- **Open:** `open Occulta.xcodeproj`
- **Build/Run:** Cmd+R in Xcode, targeting a physical iPhone 11+ (U1 chip required for NearbyInteraction)
- **Test all:** Cmd+U in Xcode, or via CLI:

  ```
  xcodebuild -project Occulta.xcodeproj -scheme OccultaTests \
    -destination 'platform=iOS Simulator,name=iPhone 17 Pro' test
  ```

  **The scheme must be `OccultaTests`, not `Occulta`.** The `Occulta` scheme has no test action,
  and `xcodebuild -list` does not even show `OccultaTests` — it reports only the two schemes marked
  shared in the container, so the one you need is absent from the listing that is supposed to tell
  you what exists. Passing `-scheme Occulta` fails with "not currently configured for the test
  action", which reads like a project-level problem rather than a wrong scheme name.

  Narrow a run with `-only-testing:OccultaTests/<SuiteStructName>` — the *struct* name, not the
  `@Suite("…")` display string. `test-without-building` is unavailable here for the same
  scheme-configuration reason, so an iterated run pays the build each time.

  Swift Testing failures print as a bare `Test case '…' failed` with no reason attached, and the
  detail does not reach stdout. Read it from the `.xcresult` the run prints at the end, or split
  the assertion into its own `@Test` and bisect — often faster than fighting `xcresulttool`.

**Requirements:** `IPHONEOS_DEPLOYMENT_TARGET` is **18.6** across all ten build configurations.
Physical device needed for NearbyInteraction.

Note the deployment target and the availability gates are different things: ML-KEM is behind
`#available(iOS 26, *)` in `PQProvider`, so the post-quantum path is live only on iOS 26+ and the
classical-only modes exist for everything between 18.6 and that.

**Secure Enclave and the test suite.** Most tests inject `TestKeyManager` or run under
`.ambientTestKeyManager` and run anywhere; about one in twenty need a real Enclave, because they
create prekeys through `PrekeyManager` or exercise a real Enclave key directly. Measure that from
CI's result bundle (its skip count), not by counting `@Test` declarations by hand. Those carry
`.enabled(if: secureEnclaveAvailable())` and report as **skipped** where one is unavailable —
notably on GitHub-hosted CI runners, which are VMs. A Simulator on bare-metal Apple Silicon does
have Enclave access and runs the full suite.

**The shared local DB key has a seam: `Manager.Ambient`** (`Services/Manager+Ambient.swift`).
Every read of keys the whole app must agree on goes through it — the local DB key above all, and
`Manager.Crypto()`'s default key manager — never through an injected `keyManager`, for the reason
`VaultManager.Backup`'s doc comment gives. In Debug a test can bind a `TestKeyManager` with
`@Test(.ambientTestKeyManager)` (`OccultaTests/AmbientTestKeyManagerTrait.swift`); Release has no
override at all. Use that trait instead of `.enabled(if: secureEnclaveAvailable())` wherever the
local DB key is the only reason for the gate. The trait fails the test if a real `Manager.Key` is
built while it is bound, because that path would pass here and fail on CI. It cannot see code that
calls the Keychain or Enclave directly — `PrekeyManager` does — so CI remains the final word.
Every gate on the local DB key alone is converted. Still gated, because they genuinely need an
Enclave — they exercise the real `Manager.Key` or create prekeys through `PrekeyManager`, whose
private keys live in it: `Key+Manipulation`, `LegacyRotationArtefactTests`,
`DuressModePrekeyTests`, `PrekeyManagerTests`, `ForwardSecrecyIntegrationTests`,
`PrekeyConsumptionOnRejectionTests`, the two prekey round-trips in `VersionCompatibilityTests`,
and three tests in `ShardFallbackGatingTests` whose receive path generates a fresh prekey batch
(`decryptSealed` calls `generateAndStoreFreshBatch` when a fallback message arrives with no
pending batch). A test that reaches that receive path needs the gate, not the trait.
The share-staging key (`ShareStagingKeyManager`) has its own, simpler seam: `ShareSession` takes
`any ShareSessionDecrypting`, so `ShareSessionTests` passes an in-memory key and runs anywhere.
Only `ShareStagingKeyManagerTests`, which tests the real Enclave key, stays gated. Each call site
passes its own key, so no `Manager.Ambient`-style override is needed there.

**With one exception, and it is not about the Enclave.** `KeychainMigrationSETests` (6 XCTest cases)
stays behind a compile-time `#if targetEnvironment(simulator)` skip and is device-only. The
Simulator *does* create SE keys there — the tempting "just gate it on `secureEnclaveAvailable()`"
was tried and reverted — but `SecItemUpdate` cannot add `kSecAttrAccessGroup` to an
SE-protected key in the Simulator, returning `-25303 errSecNoSuchAttr`, and that update is the
entire subject of the suite. A runtime gate turns six honest skips into two failures announcing
that the keychain migration strategy is unviable. Enclave availability is not the predicate;
Simulator keychain fidelity is. So a full local run's pass condition is **exactly 6 skips, all in
that suite** — any other skip means the host lacked an Enclave.

**Do not construct `Manager.Key` inside a synchronous XCTest `setUpWithError`.** The project builds
with `SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor`, so `Manager.Key` is implicitly main-actor-isolated
and its `deinit` hops executors; releasing one from that context crashes the test process
(`swift_task_deinitOnExecutorImpl` → malloc "pointer being freed was not allocated"). The failure is
disguised: xcodebuild relaunches per test and reports a green **"Executed 0 tests"**, so a suite can
stop running entirely and still look fine. The Swift Testing files that call
`secureEnclaveAvailable()` are unaffected, reaching it from a task context.

**A separate and worse problem: the old way of skipping** — `print("⚠︎ Skipping"); return`
— reports as **passed**, not skipped. So the suite's green count overstates what actually ran,
and unlike the gated tests the shortfall is invisible. None remain in the source; CI's
`xcodebuild.log` shows any that creep back, one print per pass that ran nothing. The form is not
always `guard secureEnclaveAvailable()` —
`guard let fixture = try makeX(…) else { print(…); return }` skips just as silently when the
fixture's encryption returns nil. Use `#require` for a fixture, so a failure fails. Prefer injecting a key manager, or
`.ambientTestKeyManager` where the local DB key is the reason; where neither reaches, use
`.enabled(if: secureEnclaveAvailable())` so the cost stays visible. Do not add more of the legacy
form.

So **a green CI run is not a passing test suite**: it verifies the parts that do not touch key
material. Before tagging a release, run the full suite locally on a host with an Enclave and
confirm the only skips are the six above — see the Testing Gate in `Docs/Audit/SECURITY_CHECKLIST.md`. When
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
- Feature branches prefixed with their target release, e.g. `v2.0.0/`

# Occulta Security Checklist

Run through every item before tagging a release. Each item is binary — check it only when verified, not assumed.

---

## 1. Crypto Correctness

- [ ] Every AES-GCM encryption uses a fresh 96-bit random nonce (no counter, no reuse)
- [ ] AAD is always `version ∥ sorted SecrecyContext fields` — no call site omits it
- [ ] Ephemeral P-256 private key is discarded immediately after ECDH in the v3fs path
- [ ] HKDF salt is `XOR(peerPub, ourPub)` — neither public key alone, not a constant
- [ ] Hybrid key path: P-256 shared secret XOR'd with both ML-KEM secrets *before* HKDF, not after
- [ ] `.longTermFallback` mode: `ephemeralPublicKey` in `SecrecyContext` is always `Data()` — never the sender's identity key
- [ ] `OccultaBundle` version field matches the actual secrecy mode used

## 2. Key Management

- [ ] Secure Enclave key tag (`"master.key.privacy.turtles.are.cute"`) is unique and not reused for any other purpose
- [ ] Prekey private keys are deleted from SE immediately after a successful `open()` — no deferred cleanup
- [ ] Prekey exhaustion falls back to long-term ECDH (not plaintext) and still piggybacks a fresh batch in the payload
- [ ] Soft-deleted contact key records leave no recoverable private key material in SE
- [ ] `PortingManager` migration does not re-use or export SE private keys across devices
- [ ] Local DB encryption key is derived via `ECDH(ourSEKey, G)` — verify it is inaccessible after restore to a different device

## 3. Protocol Invariants

- [ ] UWB proximity threshold (≤ 0.25 m) is enforced server-side in `ExchangeManager` before any key material is sent
- [ ] MCSession peer identity is validated before accepting key exchange data
- [ ] `QuantumKeyMaterial` is stored encrypted (not in plaintext) in SwiftData
- [ ] Identity challenge nonces are single-use — `OutstandingChallengeStore` entry deleted immediately after `verifyResponse`
- [ ] Identity challenge timestamp window is enforced (replay outside the window is rejected)
- [ ] ECDSA signature domain separation prefix is stable and applied at every signing call site
- [ ] `buildOwnedBasket` returns `nil` (no basket shown) when an `identityChallenge` envelope is present — no double-display

## 4. Data at Rest

- [ ] All contact fields are encrypted before SwiftData storage — no plaintext PII written to disk
- [ ] Shared container files (`group.com.occulta.shared/inbound/*.occ`) use `.completeFileProtection`
- [ ] Inbound `.occ` file is deleted from shared container after `processInboundSession` completes (success *and* failure paths)
- [ ] No sensitive material written to `UserDefaults`, `NSCache`, or temp files without protection class
- [ ] All writes to `FileManager.temporaryDirectory` use `Data.writeProtected(to:)` (`.completeFileProtection`) — no bare `write(to:)` calls
- [ ] `FileManager.clearTemporaryDirectory()` is called on every app launch — verify it runs before any UI is shown
- [ ] Compose staging files (media/attachments added but not yet encrypted) are removed on view disappear, encrypt-and-share completion, and individual message delete
- [ ] Outbound `.occ` files in `temporaryDirectory` are deleted by `ActivityView.onComplete` regardless of whether the user completed the share

## 5. Share Extension

- [ ] Extension matches on UTI `com.github.aibo-cora.occulta` *and* `.occ` path extension fallback — no other types accepted
- [ ] Extension writes only to its designated shared-container subdirectory, never to app-group root
- [ ] `occulta://inbound?session=<uuid>` URL contains only the UUID — no key material or plaintext in the URL
- [ ] Extension does not cache or log the ciphertext bytes
- [ ] Session files in `pending/<sessionID>/` are AES-GCM encrypted with `ShareIndexKeyManager` before being written to disk — no plaintext attachment ever lands in the shared container
- [ ] Main app decrypts session files via `ShareIndexKeyManager` before EXIF stripping and bundle encryption, and zeroes the ciphertext buffer after decryption
- [ ] Session directory (`pending/<sessionID>/`) is deleted immediately after `processShareSession` completes — on both success and failure paths
- [ ] On app launch, any `pending/` directories surviving from a previous crash are swept and deleted before processing any new session

## 6. Build Configuration

- [ ] Release scheme uses `Release` build configuration (optimisations on, assertions off)
- [ ] `Strip Debug Symbols During Copy` = YES in Release
- [ ] No hardcoded secrets, API keys, or test credentials in source or `features.plist`
- [ ] `features.plist` flags are set to their intended release values (verify `signature`, `useComposableMessage`, `useMultipleRecipientMessageFormat`)
- [ ] Entitlements contain only the capabilities actually used — no stale or over-broad entries
- [ ] App Transport Security exceptions are absent or justified
- [ ] ShareExtension and main app entitlements reference the same App Group identifier

## 7. Dependency & Supply Chain

- [ ] No third-party dependencies (confirmed: no CocoaPods, SPM, Carthage)
- [ ] All crypto uses Apple frameworks only (`CryptoKit`, `Security.framework`) — no vendored crypto code
- [ ] Xcode and macOS SDK versions are up to date for the release build

## 8. Testing Gate

**A green CI run does not satisfy this section.** GitHub-hosted macOS runners are VMs with no
Secure Enclave, so roughly 146 tests — including every prekey-isolation guard — skip there. CI
verifies the parts of the app that do not touch key material; this gate covers the parts that do.
That split is why the gate has to be run by a human on real hardware before a release is tagged.

- [ ] Full suite run **on a Mac with a working Secure Enclave** — bare metal, not a VM or CI
      runner. A Simulator on Apple Silicon is sufficient; a physical iPhone is not required:

      xcodebuild test -scheme OccultaTests \
        -destination 'platform=iOS Simulator,name=<device>' \
        -parallel-testing-enabled NO

      Leave the configuration at the scheme default. `TestKeyManager` is compiled under
      `#if DEBUG` — it is a working Secure Enclave bypass, complete with a switch that forces
      key derivation to fail, and it has no business in a shipped binary. Much of the suite
      constructs it directly, so `-configuration Release` does not compile the test target at
      all. That is a compile error, not a test failure, and it is expected.

- [ ] **Zero failures, and zero skips.** Record both counts below. A non-zero skip count means the
      host lacked an Enclave and the run does not count — it is the same blind spot as CI, not a
      pass. Verify with `secureEnclaveAvailable()` returning true rather than assuming.
- [ ] Forward secrecy tests (`OccultaTests/Forward+Secrecy/`) all pass, including prekey
      exhaustion, fallback, and pool-isolation paths
- [ ] `tempPrekey_wrongContactID_returnsNil` passes — the regression guard for the 2026-07-24
      audit's cross-contact impersonation finding. Called out by name because it was committed
      eight days before the change that broke it, went unnoticed for months, and has never
      executed in CI
- [ ] Identity challenge tests cover all three phases and the replay/timestamp rejection cases
- [ ] Secure Mode key-rotation guards pass (`GroupKeyRotationTests`, `AppLayerConfigRotationTests`,
      `EncryptedFieldCoverageTests`) — the tripwires fail on any new encrypted model property that
      has not been added to a re-encryption path

### Why this is a manual gate rather than automation

Running these in CI needs a runner with real Enclave access, which means a self-hosted runner. On a
public repository that lets a fork PR execute code on that machine — one holding Enclave access,
for a project whose threat model is coercion. Judged not worth it at current release cadence; see
`Docs/Audit/SecurityReview2026-08-12/README.md` for the full weighing. Revisit if cadence rises or
the contributor set grows beyond people with commit access.

---

**Signed off by:** ___________________  
**Release version:** ___________________  
**Date:** ___________________  
**Full-suite result:** _______ passed / _______ skipped (skipped must be 0)  
**Host used:** ___________________ (must have a working Secure Enclave)

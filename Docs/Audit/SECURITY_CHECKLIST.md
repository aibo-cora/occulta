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

## 5. Share Extension

- [ ] Extension matches on UTI `com.github.aibo-cora.occulta` *and* `.occ` path extension fallback — no other types accepted
- [ ] Extension writes only to its designated shared-container subdirectory, never to app-group root
- [ ] `occulta://inbound?session=<uuid>` URL contains only the UUID — no key material or plaintext in the URL
- [ ] Extension does not cache or log the ciphertext bytes

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

- [ ] `xcodebuild test` passes with zero failures on simulator
- [ ] Forward secrecy tests (`OccultaTests/Forward+Secrecy/`) all pass, including prekey exhaustion and fallback paths
- [ ] Identity challenge tests cover all three phases and the replay/timestamp rejection cases
- [ ] No test uses the real Secure Enclave (`TestKeyManager` only in unit tests)

---

**Signed off by:** ___________________  
**Release version:** ___________________  
**Date:** ___________________

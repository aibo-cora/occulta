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

---

### Reasoning

Always use effort=max, unless specified overwise.

## Build & Test

This is a native Xcode project with no external package manager (no CocoaPods, SPM, or Carthage).

- **Open:** `open Occulta.xcodeproj`
- **Build/Run:** Cmd+R in Xcode, targeting a physical iPhone 11+ (U1 chip required for NearbyInteraction)
- **Test all:** Cmd+U in Xcode, or via CLI:
  ```
  xcodebuild test -project Occulta.xcodeproj -scheme OccultaTests -sdk iphonesimulator
  ```
- **Run single test:** Use Xcode's test navigator diamond button, or filter by class:
  ```
  xcodebuild test -project Occulta.xcodeproj -scheme OccultaTests -sdk iphonesimulator -only-testing:OccultaTests/CryptoForwardSecrecyTests
  ```
- **Build only (simulator):**
  ```
  xcodebuild build -project Occulta.xcodeproj -scheme Occulta -destination 'generic/platform=iOS Simulator'
  ```

**Requirements:** iOS 16.0+, Xcode 16+. Physical device needed for Secure Enclave and NearbyInteraction; unit tests use `TestKeyManager` to bypass SE.

## Architecture

Occulta is an offline-first, serverless iOS contact book where physical proximity (UWB/Bluetooth) serves as the key distribution mechanism. All cryptography uses Apple frameworks only (CryptoKit + Security.framework).

Privacy and Security are paramount. There can be no vulnerabilities. Consider all possible attack vectors.

### Layers

**Crypto layer** — pure functions, no side effects, fully testable via `KeyManagerProtocol`:
- `Manager.Key` — P-256 Secure Enclave operations (create, derive, export)
- `Manager.Crypto` — AES-256-GCM encryption/decryption, ECDSA signing
- `PrekeyManager` — SE prekey batch generation and consumption (forward secrecy)
- `Crypto+Manager+ForwardSecrecy` — `seal()` / `open()` for the v3fs protocol

**Manager/Service layer** — stateful, `@Observable`, SwiftData-backed:
- `ContactManager` — SwiftData CRUD; all contact fields encrypted before storage
- `ExchangeManager` — MultipeerConnectivity + NearbyInteraction orchestration
- `PassphraseManager` — contact export/import encryption
- `PortingManager` — device migration
- `IdentityChallenge.Manager` — three-phase identity verification lifecycle (create / respond / verify)
- `IdentityChallenge.Coordinator` — `@Observable` bridge between the Manager and SwiftUI sheets
- `Manager.Security` — PIN lock state machine (`.noPIN / .pinOnly / .active / .duress`), verifier management, depth-aware contact/vault filtering, coercion-resistant gate (`appLockEnabled`). Owns `AppLayerConfig` via its own `ModelContext`. Gated by `secureMode` feature flag.
- `Manager.Blob` — forensic deniability maintenance: creates and refreshes a no-op `.occbak` file on every install so its creation timestamp predates Secure Mode activation. Provides `deriveBlobKey(from:)` and `bucketSize(for:)` shared with the Step 4 activation sequence.

**UI layer** — SwiftUI, tab-based. Views have no direct crypto knowledge; they go through managers.

### Cryptographic Protocol

**Identity key:** P-256 in Secure Enclave, tag `"master.key.privacy.turtles.are.cute"`, exported as X9.63 uncompressed (65 bytes).

**Session key derivation:** `ECDH(ourSEKey, peerPub)` → raw 32-byte secret → `HKDF-SHA256(salt: XOR(peerPub, ourPub), info: contextString)` → 32-byte AES key. When a contact has ML-KEM quantum material (all UWB-exchanged contacts do), the session key is hybrid: P-256 shared secret XOR-combined with both ML-KEM secrets before HKDF. `QuantumKeyMaterial` is stored encrypted per contact key record and threaded through all seal/open operations including identity challenges.

**Encryption:** AES-256-GCM, 96-bit random nonce per message, AAD = version ∥ sorted SecrecyContext fields. Wire format: `nonce ∥ ciphertext ∥ tag` (CryptoKit `.combined`).

**Forward secrecy (v3fs):** Per-message ephemeral P-256 key pair; contacts pre-share single-use prekeys (stored in SE). Sender pops oldest prekey, performs ECDH with ephemeral key, discards ephemeral private immediately. Recipient deletes prekey private from SE after decryption. Falls back to long-term ECDH when prekeys are exhausted; always piggybacks a fresh prekey batch (encrypted) inside the sealed payload.

**Local DB encryption:** `ECDH(ourSEKey, P-256 generator G)` → deterministic key tied to device. Inaccessible after restore to a different device.

**Wire format (`OccultaBundle`):**
```
OccultaBundle {
    version: .v1 | .v2 | .v3fs
    secrecy: SecrecyContext          // mode + ephemeralPublicKey + prekeyID (AAD)
    ciphertext: Data                  // AES-GCM(SealedPayload)
    fingerprintNonce: Data            // 16 random bytes for pre-decryption routing
    senderFingerprint: Data           // SHA-256(senderPub ∥ nonce)
}
SealedPayload {
    message: Data
    prekeyBatch: PrekeySyncBatch?    // encrypted inside, not visible to observers
    identityChallenge: IdentityChallengeEnvelope?  // non-nil → identity verification traffic
}
```

`SecrecyContext.ephemeralPublicKey` is only meaningful in `.forwardSecret` mode (carries the sender's throwaway public key). In `.longTermFallback` it is always `Data()` — never put the sender's long-term identity key there; the recipient already has it and doing so leaks identity in the cleartext header.

**Identity challenge protocol:** Rides on `.v3fs` + `.longTermFallback` so old builds decode it as a regular text message. Three phases:
1. Challenger: `createChallenge(for:)` → seals `IdentityChallengeEnvelope(.challenge)`, stores nonce in `OutstandingChallengeStore`
2. Responder: `decryptChallenge` → shows approval sheet → `respond(to:)` → seals `IdentityChallengeEnvelope(.response)` with ECDSA signature over `domainPrefix ∥ nonce ∥ timestamp ∥ challengerFingerprint`
3. Challenger: `verifyResponse` → checks signature, timestamp window, nonce match → one-shot result

Routing: `buildOwnedBasket` decrypts the outer bundle via `decryptSealed`; if `sealed.identityChallenge != nil` it hands off to `IdentityChallenge.Coordinator.handleInbound` and returns `nil` (no basket shown). The coordinator re-decrypts independently as defense-in-depth.

**Secure Mode:** PIN verifiers use `AES-GCM(HKDF(seKey, info: label ∥ pin), sentinel)` bound to a dedicated SE key (`"app.layer.key.occulta.v1"`, tag opaque to forensic tools). Normal and duress verifiers are independent. `Manager.Security` derives state from `AppLayerConfig` on every `init()` — never stores state as a plaintext flag. `persistedDepth` (encrypted signed Int on `AppLayerConfig`) encodes both routing depth and gate state: `N ≥ 0` = gate active at depth N; `-(N+1)` = gate inactive at depth N (coercion path). Blob key: `HKDF-SHA256(seKey, info: "blob-key")` — domain-separated from all PIN verifier keys.

### Key Exchange Flow

1. `ExchangeManager` starts MCNearbyServiceAdvertiser + MCNearbyServiceBrowser (Bonjour services `_peer-data-ex._tcp/_udp`)
2. Peers establish `MCSession`
3. Exchange `NIDiscoveryToken`s; `NISession` measures UWB distance
4. Proximity threshold: **≤ 0.25 m** — exchange only proceeds at this range (MITM guard)
5. Swap X9.63 public keys + ML-KEM ciphertexts; derive hybrid shared key → generate Diceware words
6. User confirms words match out-of-band; store encrypted public key + `QuantumKeyMaterial` in SwiftData

### Inbound `.occ` File Routing

iOS's system share sheet only surfaces App Extensions, not main-app document handlers. When a `.occ` file is shared from an app like WhatsApp, it reaches the `ShareExtension` rather than the main app directly.

The ShareExtension detects inbound `.occ` files before showing any UI:
- Matches on the exported UTI (`com.github.aibo-cora.occulta`) **or** `suggestedName` path extension `.occ` (fallback for apps that strip UTI metadata)
- Writes the ciphertext bytes to `group.com.occulta.shared/inbound/<uuid>.occ` (`.completeFileProtection`)
- Opens `occulta://inbound?session=<uuid>` via the responder-chain UIApplication trick

The main app's `onOpenURL` switches on `url.host`:
- `"share"` → `processShareSession` (outbound encryption flow)
- `"inbound"` → `processInboundSession` (reads shared-container file, feeds to `buildOwnedBasket`, deletes file)

### Testing

Unit tests use `TestKeyManager` (in-memory P-256, no SE access) injected via `KeyManagerProtocol`. Tests in `OccultaTests/Forward+Secrecy/` cover the full v3fs lifecycle including prekey consumption, fallback, and bundle encoding.

### Feature Flags

Runtime flags in `features.plist`, read via `FeatureFlags.isEnabled(_:)` at launch. Current notable flags:
- `signature` — ECDSA signing tab (off)
- `useComposableMessage` / `useMultipleRecipientMessageFormat` — message composer (on)
- `secureMode` — PIN lock, duress PIN, depth-aware filtering, and blob maintenance (default `true`; set `false` to develop without Secure Mode friction — `Manager.Security` stays in `.noPIN` permanently and `Manager.Blob.maintainNoOpBlob()` is skipped)

### Branches

- `develop` — integration branch; PRs target this
- `release/v*` — release branches
- Feature branches prefixed `v1.4.0/`

# OccultaCore: Specification

**Status:** Built (modularization Phase 3, steps 1 to 7); documented 2026-10-31 (step 8).
**Decisions:** [decisions.md](decisions.md). **Open items:** [bugs.md](bugs.md).
**For adopters:** [`OccultaCore/README.md`](../../../OccultaCore/README.md) (license notice, requirements, one example per primitive).
**Related:** `Docs/Audit/SECURITY_CHECKLIST.md` §7 (no dependencies; what the app's archive may contain),
`Docs/Audit/CRYPTO_REVIEW_CHECKLIST.md` (the review blocks at the top of `ShamirSecretSharing.swift` and
`TransportKeyDerivation.swift`), `Docs/General/decisions.md` (the Bug 95 subset search, which moved here).

This document says what the package is made of today. Why it is that way is in `decisions.md`.

---

## 1. What it is

`OccultaCore/` is a first-party SwiftPM package in this repository: swift-tools 6.2, Swift 6 mode, iOS 18.6,
Foundation, CryptoKit and Security only. `Package.swift` declares no package dependency and no resources, and
none may be added: a dependency here is the same supply-chain change as one in the app (SECURITY_CHECKLIST §7),
and `apple/swift-crypto` in particular is out (it ships BoringSSL bundles on Apple platforms).

It exists so the code that is not Occulta-specific can be used by another app, and so the code that is
Occulta-specific can be kept out of that app. Two library products draw the line:

| Product | For | Public surface |
|---|---|---|
| `OccultaCore` | the app, and other apps | `ShamirSecretSharing`, `PostQuantumProvider` and `PostQuantumProviderFactory`, `MLKEMKeyCheck`, `TransportKeyDerivation` |
| `OccultaFormats` | the app only | Occulta's wire and at-rest formats: `OccultaBundle`, `WireHandle`, `BodyStream`, `DepthCodec`, `BoundedJSON`, `SignedAttribute`, `IdentityChallengeEnvelope`, `IntroductionCard`, `CardIntroduction`, `CardBootstrap`, `CardMeeting`, `Basket` and `File` |

`OccultaFormats` depends on `OccultaCore` (the card formats call `MLKEMKeyCheck`). `OccultaCore` never imports
`OccultaFormats`. The boundary is a module, not `@_spi` (decisions.md).

## 2. The public primitives

All four are stateless: they keep nothing between calls. None touches a Keychain item; the provider creates
Secure Enclave keys, and the caller stores what comes back.

### 2.1 `ShamirSecretSharing`

Shamir's scheme over GF(2^8) with the AES polynomial 0x11B, for a 32-byte secret. No third-party code.

- `split(secret:threshold:shares:) throws -> [[UInt8]]`: `2 <= k <= n <= 255`, secret exactly 32 bytes. Each share is
  33 bytes: the x-coordinate (1 to n), then 32 evaluations. Coefficients come from `SecRandomCopyBytes`. The
  field multiplication is branch-free (Bug 131).
- `reconstruct(shares:maxAttempts:isCorrect:) throws -> Data`: the **only** public reconstruction. Interpolation
  cannot tell a bad share from a good one, so it tries every share, then subsets with shares left out, fewest
  first, and returns the first 32 bytes `isCorrect` accepts. Subsets with an invalid shape (duplicate x, x = 0,
  wrong length) are skipped but count toward `maxAttempts` (default 1,024, at least 1). It throws
  `noVerifiedSubset` past the cap. It needs no threshold, which is why the search runs down to pairs. It zeroes
  every rejected candidate; the accepted one is the caller's to zero.
- The unchecked `reconstruct(shares:)` is `internal`. It is reachable from the app's tests through
  `@testable import OccultaCore` and from nowhere else.
- Errors: `invalidParameters`, `invalidSecretLength`, `insufficientShares`, `invalidShareFormat`,
  `duplicateXCoordinate`, `randomGenerationFailed`, `noVerifiedSubset`.

The result is as strong as `isCorrect` and no stronger. AES-GCM is not key-committing, so a check built on a GCM
tag over ciphertext an attacker supplied can be satisfied by ciphertext crafted to open under two keys. Occulta's
backup restore passes the backup file's own tag, over ciphertext the user made (`VaultManager.Backup.verifiedKey`).
A host app with untrusted ciphertext checks a hash or MAC of the secret.

### 2.2 `PostQuantumProvider` and `PostQuantumProviderFactory`

ML-KEM-1024 key encapsulation behind a protocol, so no ML-KEM type leaves the file and every
`#available(iOS 26, *)` gate stays in `PostQuantumProvider.swift`.

- Protocol: `generateKeyPair()` (a handle that lives as long as the process), `encapsulate(peerPublicKeyData:)`,
  `decapsulate(ciphertext:privateKeyHandle:)`, `generatePersistentKeyPair()` (public key plus a blob to store),
  `decapsulate(ciphertext:keyBlob:)`, `publicKey(forKeyBlob:)`.
- `PostQuantumProviderFactory.create()` returns the Secure Enclave provider on iOS 26+ and `nil` below. A `nil`
  means the caller runs classical-only.
- Production keys are `SecureEnclave.MLKEM1024`. The persistent form is `WhenUnlockedThisDeviceOnly` with
  `.privateKeyUsage`; the blob is the key's `dataRepresentation`, usable only by this device's Enclave, and
  deleting it deletes the key. The process-lifetime form uses CryptoKit's default accessibility.
- `PostQuantumProviderFactory.createForTesting()` and the in-memory provider exist **only under `#if DEBUG`**.
  Their private keys live in app memory (the persistent blob is the 64-byte seed, i.e. the key itself), so a
  Release build must not be able to reach them.
- `encapsulate` does not run `MLKEMKeyCheck`; see bugs.md OC-2.

### 2.3 `MLKEMKeyCheck`

`isValidEncapsulationKey1024(_:) -> Bool`: the FIPS 203 §7.2 modulus check. True only for 1,568 bytes whose 1,024
12-bit coefficients are all below q = 3329. CryptoKit's `MLKEM1024.PublicKey(rawRepresentation:)` checks only the
length (observed on iOS 26.2), so a random key "parses" and `encapsulate()` then fails. The check is pure, copies
the bytes once and traps on no input. It needs no iOS 26: it is arithmetic on `Data`.

### 2.4 `TransportKeyDerivation`

`sessionKey(ecdhOutput:ownPublicKey:peerPublicKey:postQuantumSecrets:info:) throws(TransportKeyDerivation.Error) -> SymmetricKey`, the one HKDF every
Occulta transport key goes through:

```
IKM  = ecdhOutput                                 (classical)
     = ecdhOutput || sorted(secret1, secret2)     (hybrid; lexicographic)
Salt = ownPublicKey XOR peerPublicKey
key  = HKDF-SHA256(IKM, Salt, info, 32 bytes)
```

- `ecdhOutput` is the caller's: the X9.63 KDF output (SHA-256, no shared info, 32 bytes) of an ECDH it ran with its
  own key, exactly 32 bytes. No private key reaches the file.
- The public keys are x963 P-256, 65 bytes each; the secrets are 32 bytes each. Anything else throws the case that
  names it, the first that fails in this order: `invalidOwnPublicKeyLength`, `invalidPeerPublicKeyLength`,
  `invalidECDHOutputLength`, `invalidPostQuantumSecretLength`. The cases carry no data. Occulta's callers use
  `try?` and keep their `nil` (bugs.md OC-1, fixed; `decisions.md`, 2026-11-01).
- The salt is XOR, so it binds the two keys in no order, which makes both sides' salts equal. The ECDH output is
  what binds the pair.
- `info` is the caller's label and the only domain separation. Occulta passes its `SaltInfo` constants (wire
  format, in `Key+Manager.swift`); a host app passes its own. Two of Occulta's forms share a label
  (`kTransportKeyInfo`: classical long-term and classical forward-secret), and are separated by their ECDH inputs.
- It derives a key and does no more. Seal and open are the caller's own AES-GCM call. The function cannot tell
  whether a message was meant to be hybrid, so **the caller pins the post-quantum mode per peer** and never reads
  it from a message.
- Not provided, and stated in the file's review block: sender authentication, forward secrecy beyond the caller's
  key lifetimes, key confirmation, replay resistance, direction binding, zeroing of intermediates.

## 3. What is app-only, and why

`OccultaFormats` is linked by the app and the share extension. Its formats carry Occulta-identifying constants
that are wire format and cannot change: the `OCCB` magic, the `occulta-signed-attribute-v2` prefix, the
version strings. A host app using them would put Occulta's name in every message it sends, and would not
interoperate with Occulta anyway, because it manages its own keys. So they are not public API.

There is deliberately no public signer (step 6, verified 2026-10-31), no hybrid seal/open (step 3, deferred;
bugs.md OC-3), and no share type (step 4). The contact-exchange protocol and the contact book are not offered.

## 4. Isolation and language mode

`Package.swift` sets no `defaultIsolation`, so the package is nonisolated and its pure functions are callable from
any actor. It builds in Swift 6 mode. The app is `MainActor` by default (`SWIFT_DEFAULT_ACTOR_ISOLATION`). Do not
copy the app's setting into `Package.swift`.

## 5. Availability

| What | Floor |
|---|---|
| The package, `ShamirSecretSharing`, `MLKEMKeyCheck`, `TransportKeyDerivation` | iOS 18.6 (`platforms: [.iOS("18.6")]`, equal to the app's deployment target) |
| `PostQuantumProvider` implementations | iOS 26, behind `#available(iOS 26, *)` in `PostQuantumProvider.swift` and nowhere else in the package |

Below 26, `PostQuantumProviderFactory.create()` is `nil` and the classical-only modes are what runs. The
availability gate and the deployment target are different things: the app deploys to 18.6 and gates ML-KEM at 26.

## 6. How the app links it

`Occulta.xcodeproj` has one `XCLocalSwiftPackageReference` with `relativePath = OccultaCore`. The Occulta
target links both products; the `ShareExtension` target links `OccultaFormats` only (and so gets `OccultaCore` as
its dependency). The share extension keeps its own copy of the ML-KEM calls in `ShareStagingKeyManager` and does
not use `PostQuantumProvider`. The app's `Manager.Key` and the card code call `TransportKeyDerivation.sessionKey`
with Occulta's labels; `VaultManager.Backup.verifiedKey` calls the checked `reconstruct`. Outside
`OccultaFormats`, `MLKEMKeyCheck` is not called anywhere in the app (bugs.md OC-2).

## 7. Tests

| Where | What it covers |
|---|---|
| `OccultaCore/Tests/OccultaCoreAPITests` | The public API as another app would use it: a plain `import OccultaCore`, no `@testable`, no `OccultaFormats`. Shamir (round trip, error cases, `VerifiedReconstructionTests`: thresholds, group sizes, the number, kind and position of bad shares, exact attempt counts, the cap, 255 shares), `MLKEMKeyCheck`, `TransportKeyDerivation` (determinism, label separation, classical vs hybrid, secret order, both sides agree, length rejections), the provider round trip (iOS 26 only), and `ReadmeExamplesTests`, which mirrors every example in `OccultaCore/README.md` so the README cannot drift. |
| `OccultaTests` (the app's bundle) | The package's internals through `@testable import OccultaCore` or `OccultaFormats` (e.g. `gfMul`, the unchecked `reconstruct`), the formats, and the end-to-end paths that need the app (`VaultRestoreTrustTests`, the Bug 95 suite). They run under the app's one test command. |
| `OccultaTests/Interop/InteropVectors.json` | 65 vectors pinning the formats byte for byte, including the key derivations (`fsKey`, `ltKey`, `diceware`, `card.v1.longTermKey`), checked against an independent implementation. Expected values are recorded and never edited; a change that alters one breaks compatibility with existing contacts. |

The API tests cannot live in `OccultaTests`: the app's bundle links both modules, so an accidental
`import OccultaFormats` would compile there and prove nothing. Two commands, both run by CI
(`.github/workflows/ci.yml`), from `OccultaCore/`:

```
xcodebuild test -scheme OccultaCore-Package -destination 'platform=iOS Simulator,name=iPhone 17 Pro'

swift build --build-tests --explicit-target-dependency-import-check error \
  --triple arm64-apple-ios18.6-simulator --sdk "$(xcrun --sdk iphonesimulator --show-sdk-path)"
```

The `OccultaCore-Package` scheme builds every target into one directory, so an undeclared `import OccultaFormats`
still compiles under it. The second command is the check that fails on it, and is what keeps the app-only formats
out of the public API's reach. With local Xcode 27.x the simulator destination needs `,OS=26.2`, and the SDK path
is the one `xcrun --sdk iphonesimulator --show-sdk-path` prints (a literal path works where the `$(...)` form is
refused by a wrapper); CI uses Xcode 26.2, where the commands work as written.

The ML-KEM tests run only on an iOS 26+ simulator (`.enabled(if:)` on the OS version) and report as skipped
elsewhere. None of the package's own tests needs a Secure Enclave: the in-memory provider is used under `DEBUG`.

## 8. Not in the bundle (forensic check)

Occulta must not carry design docs or package notes in `Occulta.app`; an earlier release did
(`Docs/Bugs/v1.11.1/Internal-Design-Docs-Shipped-In-App-Bundle.md`). Checked 2026-10-31 against
`Occulta.xcodeproj/project.pbxproj`:

- `Docs/` and `OccultaCore/` are not synchronized folders of any target. The six
  `PBXFileSystemSynchronizedRootGroup`s are `Occulta`, `OccultaTests`, `OccultaUITests`, `OccultaPreview`,
  `ShareExtension` and `Assets`. All five `PBXResourcesBuildPhase`s are empty. The package enters the project only
  as the one local package reference and its product dependencies.
- `OccultaCore/Package.swift` declares no `resources`. `OccultaCore/README.md` is outside both targets'
  `Sources/` directories, so SwiftPM does not look at it, and the package holds no file other than `.swift`
  sources and that README.
- `OccultaTests/BundleContentsTests.swift` fails on any `.md` or `.html` in `Occulta.app` or its appexes, and CI
  runs it on every PR. It is the backstop for a regression this check cannot see.

Nothing in the `OccultaCore` target contains an Occulta-named string literal; Occulta's names appear only in
comments (file headers, the review blocks, and two doc comments that name `ExchangeManager` and
`VaultManager.Backup.verifiedKey`). Comments are not compiled in. They are in the source a host app would copy,
though (decisions.md, label policy).

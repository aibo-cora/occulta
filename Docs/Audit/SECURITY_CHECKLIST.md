# Occulta Security Checklist

Run through every item before tagging a release. Each item is binary — check it only when verified, not assumed.

Items carry the evidence they were verified against. An item with no evidence line has not been
verified in the current pass, and an unticked box with a **FAIL** or **STALE** note is a result,
not an oversight. `file:line` references are to the commit named in the sign-off block.

---

## 1. Crypto Correctness

- [x] Every AES-GCM encryption uses a fresh 96-bit random nonce (no counter, no reuse)
      — every `AES.GCM.seal` call site either passes `AES.GCM.Nonce()` (the random initialiser)
      or omits the parameter, which does the same. No call site constructs a nonce from a
      counter, a timestamp, or stored bytes.
- [ ] AAD is always `version ∥ sorted SecrecyContext fields` — no call site omits it
      — **STALE (wording).** True of the bundle/transport path, which is what the rule is for:
      `computeAdditionalAuthentication(version:secrecy:)` feeds every seal in
      `Crypto+Manager+ForwardSecrecy` and `Crypto+Manager+GroupEncrypt`. Not true as a universal
      statement, and should not be — `PIN+Manager.swift:33` (verifier sentinel),
      `ShareIndexKeyManager.swift:164`, and the `SecureMode+LayerStore` seals are separate
      key contexts with no `SecrecyContext` to bind. Rewrite to scope the rule to bundle
      encryption, then this can be ticked; leaving it universal makes a correct codebase read
      as a violation.
- [x] Ephemeral P-256 private key is discarded immediately after ECDH in the v3fs path
      — `Key+Manager.swift:332` creates it with `kSecAttrIsPermanent: false`, so it is never
      written to the keychain; the `SecKey` is a local in `deriveOutboundKey` and is released
      at scope exit.
- [x] HKDF salt is `XOR(peerPub, ourPub)` — neither public key alone, not a constant
      — `Data(zip(recipientMaterial, ephemeralPublicKeyData).map { $0 ^ $1 })`, documented at
      `Key+Manager.swift:1290`.
- [ ] Hybrid key path: P-256 shared secret XOR'd with both ML-KEM secrets *before* HKDF, not after
      — **STALE.** The code **concatenates**: `IKM = ECDH ‖ sorted(kem₁, kem₂)`, HKDF'd with the
      ECDH salt (`Key+Manager.swift:1260`, mirrored in `TestKeyManager`). Concatenation is the
      correct KEM combiner — XOR into a fixed-width value discards entropy and is not what any
      hybrid construction recommends — so the **code is right and this item is wrong**. Sorting
      the two secrets lexicographically is what makes both sides agree on the order. Reword to
      "concatenated, ML-KEM secrets in canonical sorted order".
- [x] `.longTermFallback` mode: `ephemeralPublicKey` in `SecrecyContext` is always `Data()` —
      never the sender's identity key
      — single construction site, `Crypto+Manager+KeyDerivation.swift:47`, covering both
      `.longTermFallback` and `.longTermNoPQ`. The identity-challenge bundle does the same
      (`IdentityChallenge+Manager.swift:422`).
- [x] `OccultaBundle` version field matches the actual secrecy mode used
      — enforced cryptographically rather than by assertion: version and `SecrecyContext` are
      both bound into the AAD (`computeAdditionalAuthentication(version:secrecy:)`), so any
      mismatch fails authentication at the receiver instead of producing a wrong-but-openable
      bundle. The codebase has already met this the hard way — the comment at
      `Contact+Manager.swift:1028` records that passing a capability case rather than `.v4`
      embeds its own raw value in the AAD while the receiver reconstructs `v4`, and the result
      is an authentication failure. Group path pairs `.v4` with `mode: .group`
      (`Crypto+Manager+GroupEncrypt.swift:151, 154, 172`); the 1:1 paths derive mode and
      version from the same `targetVersion` resolution (`:1033`, `:1040`).

## 2. Key Management

- [x] Secure Enclave key tag (`"master.key.privacy.turtles.are.cute"`) is unique and not reused
      for any other purpose
      — eight distinct tags, one per purpose: identity (`master.key.…`), local DB SE
      (`local.db.se.key.occulta` + `.staged` + `.superseded`), local DB random
      (`local.db.random.key.occulta` + `.staged`), vault (`vault.key.occulta.v1`), Secure Mode
      (`app.layer.key.occulta.v1`). No tag serves two roles.
- [ ] Prekey private keys are deleted from SE immediately after a successful `open()` — no
      deferred cleanup
      — **FAIL on the group path, introduced by this release.** The 1:1 path is correct:
      `open` at `Contact+Manager.swift:1574`, `consume(prekey:)` at `:1581`, nothing between
      them that can throw. The group path opens the recipient slot at `:1795` and consumes at
      `:1841`, and this release inserted the sender-ephemeral-signature gate at `:1822` in
      between — a gate whose whole purpose is to `throw`. A bundle that opens successfully and
      then fails that check leaves the prekey alive in the Secure Enclave.

      To reach it an attacker needs prekey material we issued, which is the same bar as the
      finding the gate was added to close, so this is not open to arbitrary third parties. What
      it costs is the forward-secrecy property the consume exists to provide: an attacker who
      can deliver `.occ` files can hold a prekey open indefinitely, and every message ever
      sealed to it stays decryptable if the device is later seized. Normal traffic is
      unaffected — a capable sender always signs, so the gate does not fire.

      Fix is an ordering decision rather than a one-liner, which is why it is reported and not
      applied: consuming before the check means a rejected forgery also runs
      `clearPendingBatch()`, letting an attacker manipulate batch state. Consuming the prekey
      before the gate while leaving the batch bookkeeping after it separates the two correctly.
- [x] Prekey exhaustion falls back to long-term ECDH (not plaintext) and still piggybacks a
      fresh batch in the payload
      — with `contactPrekey == nil` the outbound path still seals, taking `.longTermFallback` /
      `.longTermNoPQ` (`Crypto+Manager+KeyDerivation.swift:46`); nothing is ever sent in the
      clear. The pending batch is loaded independently of whether a prekey was popped
      (`Contact+Manager.swift:1051`) and rides the bundle either way. Precision on "fresh":
      batches are generated on the *receive* side, when a message arrives and no batch is
      pending (`:1587`, `:1844`) — not at the moment of send-side exhaustion. Shard content is
      dropped rather than downgraded when no prekey is available (`:1073`), so shard material
      never travels without forward secrecy.
- [x] Soft-deleted contact key records leave no recoverable private key material in SE
      — the row is soft-deleted (`deletionToken` set, `Contact+Manager.swift:484`) but the key
      material is hard-deleted: `PrekeyManager.deleteAllKeys(for:)` at `:486` enumerates SE keys
      and deletes every one tagged `prekey.<contactID>.`. ML-KEM leaves no per-contact residue
      to clean — `SecureEnclave.MLKEM1024.PrivateKey` is held as an in-memory handle for the
      duration of the exchange and never persisted under a tag (`PQProvider.swift:95`); what is
      stored is the pair of 32-byte shared secrets, encrypted. Caveat: `deleteAllKeys(for:)`
      returns silently if `SecItemCopyMatching` fails, so deletion is best-effort with no
      retry and no signal.
- [ ] ~~`PortingManager` migration does not re-use or export SE private keys across devices~~
      — **STALE: no such type.** `PortingManager` does not exist anywhere in the repository.
      The property it was guarding still holds by construction — the only
      `SecKeyCopyExternalRepresentation` calls in the app extract **public** keys
      (`PrekeyManager.swift:70`, `ShareIndexKeyManager.swift:147`, and `TestKeyManager`'s
      in-memory pairs). Delete this item or re-point it at whatever replaced the component.
- [x] Local DB encryption key is inaccessible after restore to a different device
      — **wording amended.** The item described `ECDH(ourSEKey, G)`; the derivation is now
      hybrid — `HKDF(ECDH(localDB_SE_priv, G) ‖ keychain_random)`, salted with the SE public key
      (`Key+Manager.swift:432`). Both halves are device-bound and the property is stronger than
      before: the SE half is `kSecAttrTokenIDSecureEnclave` with `.privateKeyUsage` only and
      `WhenUnlockedThisDeviceOnly` (`:506`), so it is non-exportable and non-migratable; the
      random half is `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (`:562`), so it does not
      travel in an encrypted backup. Neither half can be reconstructed on another device.

## 3. Protocol Invariants

- [x] UWB proximity threshold (≤ 0.25 m) is enforced in `ExchangeManager` before any key
      material is sent
      — `Exchange+Manager.swift:638`: `guard let distance = object.distance,
      distance.isLessThanOrEqualTo(0.25) else { continue }`, ahead of every `sendIdentity` /
      `sendCiphertext` call, with `guard self.exchangeStatus == nil` ensuring the protocol
      starts exactly once.
- [ ] MCSession peer identity is validated before accepting key exchange data
      — **FAIL as written; the property is provided elsewhere.** There is no peer
      authentication at the MultipeerConnectivity layer: the session is built with
      `securityIdentity: nil` (`Exchange+Manager.swift:148`), every invitation is accepted
      unconditionally (`invitationHandler(true, …)`, `:767`), the browser invites every peer
      that is not us (`:755`), and no `session(_:didReceiveCertificate:fromPeer:)` is
      implemented — which means MC auto-accepts all certificates. `encryptionPreference:
      .required` encrypts the link but authenticates nobody.

      What actually gates key exchange is physical: a peer's discovery token must arrive over
      MC *and* that token must range at ≤ 0.25 m before any identity is sent (`:638`), with
      `guard self.exchangeStatus == nil` allowing the protocol to start exactly once. The
      residual risk is a race — two devices both inside 25 cm, and the attacker's ranging lands
      first. The designed answer to that is the diceware confirmation: both sides derive words
      from the completed shared secret and compare them out of band
      (`KeyExchange.swift:236`), which no attacker-in-the-middle can match.

      Reword the item to name the control that exists — proximity plus out-of-band word
      comparison — or implement `didReceiveCertificate`. As written it asserts a check that is
      not there.
- [x] `QuantumKeyMaterial` is stored encrypted (not in plaintext) in SwiftData
      — JSON-encoded, then through `cryptoManager.encrypt` (hybrid local DB key + AAD) before
      it reaches the model (`Contact+Manager.swift:548–565`). That is the only write site
      besides the rotation path, which reseals rather than storing anew
      (`Contact+Model+Reencrypt.swift:118`).
- [x] Identity challenge nonces are single-use — `OutstandingChallengeStore` entry deleted
      immediately after `verifyResponse`
      — `store.remove(nonce:)` on every exit from the verify path
      (`IdentityChallenge+Manager.swift:331, 347, 373, 384`), rejection paths included.
- [x] Identity challenge timestamp window is enforced (replay outside the window is rejected)
      — `guard age < IdentityChallenge.timestampStaleThreshold` (`:243`).
- [ ] ECDSA signature domain separation prefix is stable and applied at every signing call site
      — **FAIL: three sites of four.** Prefixed and stable: identity challenge
      (`"occulta-identity-challenge-v1"`, `IdentityChallenge+Crypto.swift:93`) and both vault
      attribute sites (`"occulta-signed-attribute-v2"`, `SignedAttribute.swift:134`, used by
      `Vault+Manager+Backup.swift:341` and `Vault+Manager+Shards.swift:95`).

      Not prefixed: `senderEphemeralSignature` signs the bare ephemeral public key —
      `signData(secrecyContext.ephemeralPublicKey)`, `Crypto+Manager+GroupEncrypt.swift:207`.
      The same long-term identity key therefore signs both domain-tagged payloads and a raw
      65-byte X9.63 point. No confusion is reachable today, because that point always begins
      `0x04` and is exactly 65 bytes while both prefixes begin with ASCII `o` — the byte spaces
      do not overlap. But that is a property of the encodings, not a separation anyone
      designed, and it is the only thing standing between these two uses of one key. Give the
      ephemeral signature its own prefix.
- [x] `buildOwnedBasket` returns `nil` (no basket shown) when an `identityChallenge` envelope
      is present — no double-display
      — `OccultaApp.swift:673–681`.

## 4. Data at Rest

- [x] All contact fields are encrypted before SwiftData storage — no plaintext PII written to disk
      — the `String` properties on `Contact.Profile` hold base64 of AES-GCM ciphertext, not
      text: every field goes through `crypto.encrypt(...)?.base64EncodedString()` on the way in
      (`Contact+Manager.swift:244–338`) and `String.decrypt()` on the way out
      (`Crypto+Manager.swift:202`). `identifier` included — it is encrypted once in the
      never-before-persisted branch (`:367`) and every later lookup compares the stored
      ciphertext as an opaque string. Non-PII plaintext that remains: `encryptionScheme` (an
      `Int` tag) and the relationship keys.

      One fail-open worth closing: `:367` ends `?? rawIdentifier`, so if key derivation fails
      at contact creation the raw UUID is stored in the clear. Same shape as the `?? ""`
      fallbacks on the other fields, where the consequence is only a lost value.
- [x] Shared container files use `.completeFileProtection`
      — `inbound/<uuid>.occ` written with `options: .completeFileProtection`
      (`ShareViewController.swift:474`); `pending/<sessionID>/` gets `URLFileProtection.complete`
      on the directory at creation (`:184`) and each attachment is written with the option
      (`:302, :336, :474`). `manifest.enc` used to be written without the option and given
      `.complete` immediately afterwards via `setResourceValue`, leaving a brief window at the
      default class; it now passes the option to the write like every other write in the file
      (`:257`).
- [x] Inbound `.occ` file is deleted from shared container after processing completes
      (success *and* failure paths)
      — `defer { if openedThroughShareExtension { try? FileManager.default.removeItem(…) } }`
      wrapping the whole task (`OccultaApp.swift:518`). Also covers the locked-app path, where
      the bytes are queued in memory and the function returns early.
- [x] No sensitive material written to `UserDefaults`, `NSCache`, or temp files without
      protection class
      — `UserDefaults`/`@AppStorage` holds four booleans only: `showFingerprints`,
      `showTrustSummary`, `hasCompletedOnboarding`, `vault.postRestoreActionNeeded`. No key
      material, no identifiers, and no key whose name discloses Secure Mode.
- [x] All writes to `FileManager.temporaryDirectory` use `Data.writeProtected(to:)`
      (`.completeFileProtection`) — no bare `write(to:)` calls
      — **was FAIL, fixed this pass.** `IdentityChallenge+Coordinator.swift:285` wrote the
      outbound challenge/response `.occ` with a bare `write(to:)`, landing it at the default
      protection class. Now `writeProtected`. Repository-wide sweep confirms every remaining
      `write(to:)` passes `.completeFileProtection` explicitly.
- [x] `FileManager.clearTemporaryDirectory()` is called on every app launch
      — `OccultaApp.init()` (`:92`). Note it dispatches through `Task.detached`, so it is
      *initiated* before any UI and not necessarily *complete* before it; the item's "verify it
      runs before any UI is shown" is therefore satisfied only in the weaker sense.
- [x] Compose staging files are removed on view disappear, encrypt-and-share completion, and
      individual message delete
      — three `removeItem` paths in `ComposeViewModel.swift:397, 403, 411`.
- [x] Outbound `.occ` files in `temporaryDirectory` are deleted regardless of whether the user
      completed the share
      — `ActivityView`'s `onComplete` handlers call `removeItem` unconditionally, before the
      `if completed` branch (`ComposableMessage.swift:135`, `ContactDetailV2.swift:162`,
      `GroupDetailV3.swift:154`, `ContactDetailV3.swift:165`). The two `ShareActivityView`
      sheets delete in `.onDisappear` (`OccultaApp.swift:289, 299`), which covers the
      identity-challenge and share-extension outputs.

## 5. Share Extension

- [ ] Extension matches on UTI `com.github.aibo-cora.occulta` *and* `.occ` path extension
      fallback — no other types accepted
      — **STALE (scope).** Accurate for the *inbound* branch: `looksLikeOCC`
      (`ShareViewController.swift:410`) matches exactly those two and nothing else. But the
      extension's activation rule accepts any file and any image, up to 20 each
      (`ShareExtension/Info.plist`) — that is the outbound encrypt-for-contact flow, which is
      the extension's main purpose. Reword to cover both branches; as written it claims a
      restriction the extension does not have and should not have.
- [x] Extension writes only to its designated shared-container subdirectory, never to app-group root
      — four write sites, all under `pending/<sessionID>/` or `inbound/`. The only app-group-root
      path touched is `ShareIndex.sqlite`, opened read-only.
- [x] `occulta://inbound?session=<uuid>` URL contains only the UUID — no key material or
      plaintext in the URL
      — `:486`, and the outbound `occulta://share?session=<uuid>` at `:347`. The main app
      re-parses through `UUID(uuidString:)` before use, so no path separator can survive
      (`OccultaApp.swift:481`).
- [x] Extension does not cache or log the ciphertext bytes
      — no `print`, `NSLog`, `os_log`, `debugPrint`, or `Logger` anywhere in the extension target.
- [x] Session files in `pending/<sessionID>/` are AES-GCM encrypted with `ShareIndexKeyManager`
      before being written to disk — no plaintext attachment ever lands in the shared container
      — both intake paths encrypt before writing and zero the plaintext buffer first
      (`:299–302` file representation, `:334–336` data representation). Filenames are
      positional (`0.tmp`, `1.tmp`); real names live only inside the encrypted manifest.
- [x] Main app decrypts session files via `ShareIndexKeyManager` before EXIF stripping and
      bundle encryption, and zeroes the ciphertext buffer after decryption
      — `OccultaApp.swift:879–882`, then EXIF strip at `:887`, then `encryptBundle` at `:909`.
      A `defer` at `:871` zeroes accumulated plaintext on every exit from the block, throw
      included.
- [x] Session directory (`pending/<sessionID>/`) is deleted immediately after
      `processShareSession` completes — on both success and failure paths
      — success `:928`, failure `:934`.
- [x] On app launch, any `pending/` directories surviving from a previous crash are swept and
      deleted before processing any new session
      — `cleanupPendingSessions()` on `scenePhase == .active` (`OccultaApp.swift:348`), which
      fires on launch and on every foreground return. Sessions with no manifest, an unreadable
      manifest, or one older than an hour are removed
      (`ContactManager+ShareIndex.swift:123`). Note the comment at `:156` calls manifest-less
      session files "plaintext" — they are ciphertext under the share key; the deletion is
      still right, the reason given for it is stale.

## 6. Build Configuration

Verified against a real Release archive built for `generic/platform=iOS` at the commit in the
sign-off block, not against project settings alone.

- [x] Release scheme uses `Release` build configuration (optimisations on, assertions off)
      — `Occulta.xcscheme`: Archive and Profile are `Release`; Run/Test/Analyze are `Debug`,
      which is correct. `ENABLE_NS_ASSERTIONS = NO` in the Release config (`project.pbxproj:752`).
- [ ] `Strip Debug Symbols During Copy` = YES in Release
      — **FAIL as written, PASS in substance.** `COPY_PHASE_STRIP = NO` in both Debug and
      Release (`project.pbxproj:684, 748`). But that legacy setting governs files copied by a
      Copy Files phase, not the product, and the shipped product is stripped: `nm -a` on the
      archived `Occulta` binary reports **zero** `OSO`/`SO`/`FUN` debug-map entries, and the
      same holds for `ShareExtension.appex`. Full `.dSYM`s are produced for all three targets.
      Rewrite the item to assert the property (no debug map in the archived binary, dSYMs
      present) rather than the setting, and it passes on measurement.
- [x] No hardcoded secrets, API keys, or test credentials in source or `features.plist`
      — no secret-shaped literals in the app or extension targets; no hardcoded PINs. The SE
      tags are keychain identifiers, not secrets, and are covered by item 2.1.
- [x] `features.plist` flags are set to their intended release values
      — `signature: false`, `useComposableMessage: true`,
      `useMultipleRecipientMessageFormat: true`, plus `secureMode: true` and
      `enableShamirShardSharing: true`. **Confirm `signature: false` is intended for this
      release** — it is the one flag whose value is not self-evidently the shipping one.
- [x] Entitlements contain only the capabilities actually used — no stale or over-broad entries
      — both `Occulta.entitlements` and `ShareExtension.entitlements` contain exactly one key,
      `com.apple.security.application-groups`. The `aps-environment` entries that appear in
      stale copies under `.claude/worktrees/` are not in the build.
- [x] App Transport Security exceptions are absent or justified
      — no `NSAppTransportSecurity` key in either `Info.plist`. Consistent with an app that
      makes no network requests.
- [x] ShareExtension and main app entitlements reference the same App Group identifier
      — `group.com.occulta.shared` in both.

### Shipped bundle contents — new item, and it fails

- [x] The app bundle contains no internal documentation, design notes, or planning material
      — **was FAIL, fixed this pass.** The Release archive shipped **16 internal documents,
      ~350 KB**, in `Occulta.app/` alongside the binary:

      forensic-trace-avoidance.md      (37 KB)   secure-mode-architecture.html  (28 KB)
      plan.md                          (70 KB)   scenarios.md                   (38 KB)
      SECURE_MODE_DECRYPT_CONTRACT.md            SecureMode+RotationContract.md
      LayerStore.md                              VAULT_SSS_GUIDE.md
      VAULT_BACKUP_GUIDE.md                      SHARD_PROTOCOL_CASES.md
      FORWARD_SECRECY_GUIDE.md                   forward_secrecy_flow.md
      contact-backup-analysis.md                 classification-mockup.html
      README.md                                  SHARE_EXTENSION_PLAN 16.32.42.md

      This contradicts the project's stated forensic-trace invariant more directly than any
      code path audited here. The bundle is identical for every install, so it proves nothing
      about whether *this* user has Secure Mode configured — but a file named
      `forensic-trace-avoidance.md`, sitting in the app directory of a seized device, tells an
      examiner that the app is built to resist them, and `secure-mode-architecture.html` plus
      `SECURE_MODE_DECRYPT_CONTRACT.md` hand a coercer the full duress design, including which
      tells to look for and what to demand. The threat model assumes the adversary knows the
      app; it does not assume the app hands them the design docs.

      Cause: these files live inside the `Occulta/` source tree, which is an Xcode 16
      file-system-synchronized root group. Every non-source file under a synchronized folder
      is copied into the bundle by default — nobody added them; nobody had to.

      **Fix.** Fifteen are now listed in the `membershipExceptions` of the Occulta target's
      exception set, which is how a synchronized group excludes a path. `README.md` came in
      separately, as an explicit `PBXBuildFile` in Copy Bundle Resources, and that entry is
      removed; its `PBXFileReference` stays so the file is still visible in the navigator. All
      sixteen remain on disk and in git — this changes what ships, not what exists.

      Paths in a `membershipExceptions` list must be quoted whenever they contain anything
      outside the unquoted-token charset. Two here do: a `+` in `Forward+Secrecy` and
      `SecureMode+RotationContract.md`, and a space in `SHARE_EXTENSION_PLAN 16.32.42.md`.
      Leaving them bare makes the whole project unreadable — `xcodebuild` fails with
      "Unable to read project", not with a parse error pointing at the line.

      **Verified** by re-archiving: `find` reports zero `.md` and zero `.html` anywhere in the
      archive, including both appexes. What remains in `Occulta.app/` is the binary,
      `Info.plist`, `PkgInfo`, `PlugIns/`, the two app icons, `Assets.car`,
      `eff_large_wordlist.txt`, `features.plist`, and the five swift-crypto bundles — the last
      of those being §7.2, deliberately left in place for this release.

## 7. Dependency & Supply Chain

- [ ] No third-party dependencies (confirmed: no CocoaPods, SPM, Carthage)
      — **FAIL.** The project has an SPM dependency: `apple/swift-crypto` (pinned 4.2.0),
      which pulls `apple/swift-asn1` (1.5.1). Declared at `project.pbxproj:1055`, resolved in
      `project.xcworkspace/xcshareddata/swiftpm/Package.resolved`. Three products are linked:
      `Crypto`, `CryptoExtras`, `_CryptoExtras`. CLAUDE.md's "no external package manager"
      is stale for the same reason.
- [ ] All crypto uses Apple frameworks only (`CryptoKit`, `Security.framework`) — no vendored
      crypto code
      — **FAIL as stated.** Five swift-crypto resource bundles ship inside the app, including
      `swift-crypto_CCryptoBoringSSL.bundle` and `swift-crypto_CryptoBoringWrapper.bundle` —
      vendored BoringSSL.

      **The dependency appears to be dead weight.** `import Crypto` occurs in exactly one file
      (`Crypto+Manager.swift:14`), next to `import CryptoKit`. Commenting it out and building
      the app for iOS Simulator **succeeds** — verified this pass, edit reverted. Nothing in
      the app uses a swift-crypto-only API, and ML-KEM comes from CryptoKit's SE-backed
      `MLKEM1024`, gated on iOS 26 in `PQProvider.swift`, not from swift-crypto. So the actual
      crypto in use *is* Apple-framework-only and the item's intent holds; what fails is that
      an unused third-party package still ships vendored BoringSSL in the shipping binary.

      Recommended: drop the three package product dependencies and the package reference, then
      re-archive and confirm the bundles are gone. Not done here — removing a dependency is a
      release-scope decision.
- [x] Xcode and macOS SDK versions are up to date for the release build
      — Xcode 26.2 (17C52), iOS SDK 26.2, macOS 26.5.2. `SWIFT_VERSION = 5.0` (language mode,
      not toolchain). `IPHONEOS_DEPLOYMENT_TARGET = 18.6` uniformly across all ten
      configurations — note CLAUDE.md still says iOS 16.0+, which is stale by two major
      versions and worth correcting, though nothing depends on it.

## 8. Testing Gate

**A green CI run does not satisfy this section.** GitHub-hosted macOS runners are VMs with no
Secure Enclave, so roughly 146 tests — including every prekey-isolation guard — skip there. CI
verifies the parts of the app that do not touch key material; this gate covers the parts that do.
That split is why the gate has to be run by a human on real hardware before a release is tagged.

- [x] Full suite run **on a Mac with a working Secure Enclave** — bare metal, not a VM or CI
      runner. A Simulator on Apple Silicon is sufficient; a physical iPhone is not required:

      xcodebuild test -scheme OccultaTests \
        -destination 'platform=iOS Simulator,name=<device>' \
        -parallel-testing-enabled NO

      Leave the configuration at the scheme default. `TestKeyManager` is compiled under
      `#if DEBUG` — it is a working Secure Enclave bypass, complete with a switch that forces
      key derivation to fail, and it has no business in a shipped binary. Much of the suite
      constructs it directly, so `-configuration Release` does not compile the test target at
      all. That is a compile error, not a test failure, and it is expected.

- [x] **Zero failures.** 716 Swift Testing tests across 162 suites, plus 36 XCTest cases —
      746 passed, 0 failed, 6 skipped. Run serially (`-parallel-testing-enabled NO`).
- [ ] **Zero skips**, excluding `KeychainMigrationSETests`
      — **the item is unachievable as originally written, and the exclusion is the fix.**
      6 tests skipped, all in `KeychainMigrationSETests`, which throws `XCTSkip` from
      `setUpWithError` behind `#if targetEnvironment(simulator)` — a *compile-time* gate that
      does not consult `secureEnclaveAvailable()`. On bare-metal Apple Silicon the Simulator
      does reach the Enclave, so these six cannot run on any host this gate permits; only a
      physical device runs them. CI already skips the same suite by name
      (`-skip-testing:OccultaTests/KeychainMigrationSETests`). Either accept the exclusion, or
      change the gate to `.enabled(if: secureEnclaveAvailable())` so a bare-metal Simulator
      run covers them — until then, a skip count of 6 with these six names is the pass
      condition, and any *other* skip means the host lacked an Enclave and the run does not
      count.
- [x] Forward secrecy tests (`OccultaTests/Forward+Secrecy/`) all pass, including prekey
      exhaustion, fallback, and pool-isolation paths
- [x] `tempPrekey_wrongContactID_returnsNil` passes — the regression guard for the 2026-07-24
      audit's cross-contact impersonation finding. Called out by name because it was committed
      eight days before the change that broke it, went unnoticed for months, and has never
      executed in CI
- [x] Identity challenge tests cover all three phases and the replay/timestamp rejection cases
- [x] Secure Mode key-rotation guards pass (`GroupKeyRotationTests`, `AppLayerConfigRotationTests`,
      `EncryptedFieldCoverageTests`) — the tripwires fail on any new encrypted model property that
      has not been added to a re-encryption path

### Why this is a manual gate rather than automation

Running these in CI needs a runner with real Enclave access, which means a self-hosted runner. On a
public repository that lets a fork PR execute code on that machine — one holding Enclave access,
for a project whose threat model is coercion. Judged not worth it at current release cadence; see
`Docs/Audit/SecurityReview2026-08-12/README.md` for the full weighing. Revisit if cadence rises or
the contributor set grows beyond people with commit access.

---

## Blockers for this release

1. ~~Internal design docs ship inside the app bundle~~ — **fixed**, verified against a fresh
   archive. See §6.
2. ~~`manifest.enc` written before its protection class is set~~ — **fixed**. See §4.2.
3. **Prekey survives a rejected group bundle** (§2.2) — **new, and this release caused it.** The
   sender-signature gate added at `Contact+Manager.swift:1822` sits between opening the recipient
   slot and consuming the prekey, so a bundle that opens and is then rejected leaves the prekey
   live in the Enclave. The highest-severity item found in this pass, and the only open one that
   is a defect rather than a wording problem. Needs an ordering decision — see §2.2.
4. **Unused swift-crypto dependency ships vendored BoringSSL** (§7.1, §7.2) — **accepted for
   1.10.2.** The package is not load-bearing and removing it would delete five resource bundles
   from the shipping app, but pulling a dependency is not a release-week change. The crypto
   actually in use is Apple-framework-only, so the property the checklist cares about holds;
   what ships is dead weight, not a weakness. Revisit before the next tag.
5. **`senderEphemeralSignature` has no domain-separation prefix** (§3.6) — the only one of four
   signing sites without one, and it shares the long-term identity key with the three that have
   it. Not reachable today; the encodings happen not to overlap. Give it a prefix.
6. Stale item wordings to correct so future passes measure the right thing: §1.2, §1.5, §2.5,
   §3.2, §5.1, §6.2, §8's skip rule. CLAUDE.md's "no external package manager" line, and its
   "iOS 16.0+" — the deployment target is 18.6.

Every item now carries a result. Two smaller things recorded in place rather than raised here:
`deleteAllKeys(for:)` is best-effort with no signal on failure (§2.4), and contact-identifier
encryption falls open to the raw UUID if key derivation fails (§4.1).

---

**Signed off by:** ___________________
**Release version:** 1.10.2
**Date:** 2026-08-13
**Full-suite result:** 746 passed / 0 failed / 6 skipped (all `KeychainMigrationSETests` — see §8)
**Host used:** Apple Silicon, iPhone 17 Pro Simulator, bare metal (Secure Enclave available)
**Archive inspected:** Release, `generic/platform=iOS`, `CODE_SIGNING_ALLOWED=NO`

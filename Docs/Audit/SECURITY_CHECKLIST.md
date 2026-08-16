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
- [x] Prekey private keys are deleted from SE immediately after a successful `open()` — no
      deferred cleanup
      — **was FAIL on the group path, fixed this pass.** The 1:1 path was always correct: `open`
      at `Contact+Manager.swift:1574`, `consume` at `:1581`, nothing between them that can throw.
      The group path had **three** throw sites between the prekey being used and deleted, each
      leaving it alive in the Enclave:

      | # | Throw | Where | Added by 1.10.2? |
      |---|-------|-------|------------------|
      | 1 | `senderEphemeralSignatureMismatch` | `Crypto+Manager+GroupDecrypt.swift` — **inside** `findAndOpenRecipientSlot` | No |
      | 2 | `missingSenderEphemeralSignature`  | `Contact+Manager.swift:1826` | Yes |
      | 3 | `senderSignatureCapabilityUnknown` | `Contact+Manager.swift:1830` | Yes |

      Site 1 predates this release, arriving with the 2026-07-24 remediation, so the release
      widened an existing gap rather than opening it.

      **Fix: consume at the moment the slot opens.** A function-scope `defer` in
      `findAndOpenRecipientSlot` deletes the prekey on every exit — the successful return and
      the signature-mismatch throw alike — so by the time sites 2 and 3 run in `openGroup` the
      key is already gone. Reordering inside `openGroup` could not have reached site 1, which
      throws in a callee that computed the prekey as a local and dropped it on the way out.

      The returned `Prekey?` now reports what *was* consumed rather than instructing the caller
      to consume it, and `openGroup`'s block keeps only the model-side bookkeeping —
      deliberately still behind the gates, so a rejected bundle cannot drive `clearPendingBatch`
      or `generateAndStoreFreshBatch`.

      **The cost, accepted knowingly.** A rejected bundle now destroys a prekey, so someone
      holding the batch we published to a contact can burn all 15 with bundles that open and
      then fail. That is the fail-secure direction — the keys are gone, so nothing sealed to
      them survives a later seizure — and it self-heals: once the batch is exhausted the
      contact's next send falls back to long-term ECDH, which arrives normally and triggers a
      fresh batch. The trade is availability under an active attacker for forward secrecy under
      coercion, which is the right way round for this threat model. Bug 82 is the one benign
      trigger and is deferred; when it fires the message is lost either way, and now its prekey
      is destroyed rather than left exposed. (Narrowed 2026-08-15: the benign trigger is
      specifically **82b**, the forward-secret half, which remains deferred. 82a cannot reach
      this path — fallback slots consume no prekey.)

      Guarded by `PrekeyConsumptionOnRejectionTests`, which were verified to fail against the
      previous behaviour: 4 of its 5 cases break when the `defer` is removed. The fifth asserts
      a non-recipient consumes nothing, and holds either way by design.

      **A second defect under the same item, independent of ordering — also fixed.** `consume`
      returns 1/0 and both call sites discarded it, so a failed `SecItemDelete` at what its own
      doc calls "the exact moment forward secrecy is established" passed unnoticed on the
      success path. The status is now inspected inside `consume`. It stays best-effort in
      release: the message is already decrypted by then, so throwing would discard legitimate
      content to report something the user cannot act on, and there is nothing to retry — the
      failure modes are an unavailable keychain and `errSecItemNotFound`.

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
- [x] ECDSA signature domain separation prefix is stable and applied at every signing call site
      — **was FAIL on one site of four, fixed this pass.** Prefixed and stable: identity
      challenge (`"occulta-identity-challenge-v1"`, `IdentityChallenge+Crypto.swift:93`) and
      both vault attribute sites (`"occulta-signed-attribute-v2"`, `SignedAttribute.swift:134`).
      `senderEphemeralSignature` signed the bare ephemeral public key, so one identity key
      signed both domain-tagged payloads and a raw 65-byte X9.63 point. Nothing collided —
      the point begins `0x04`, both prefixes begin with ASCII `o` — but the collision space was
      exactly "65-byte P-256 public key", a shape this app handles everywhere, and the safety
      was one call site deep.

      Now `"occulta-sender-ephemeral-v1" ‖ ephemeralPublicKey`, **gated on a capability tier**
      rather than applied unconditionally. Changing what we sign changes what receivers verify
      against, and 1.10.0/1.10.1 verify the bare form — prefixing for them would reject our
      messages outright, in the one direction no patch can reach. So senders prefix only for
      recipients at `.prefixedSenderSignatureCapable` (1.10.2+, marker byte 0x08), resolved per
      recipient because a group's members can be on different builds.

      Receivers accept both forms, and must, for as long as 1.10.0/1.10.1 senders exist. That
      means the separation currently constrains what new senders emit, not what receivers
      accept — **the bare arm in `verifySenderEphemeralSignature` is transitional and should be
      removed once those versions are out of circulation.** Until then the property this buys
      is that no signature minted by a current build can be replayed into a future bare-signing
      context. `signData`'s documentation carries the rule for whoever adds the next site.

      **Known cost, filed as Bug 83.** The tier comes from a high-water marker that rises and
      never falls, so a contact who downgrades below 1.10.2 keeps receiving prefixed signatures
      their build cannot verify, with no way for either side to correct it. This is the first
      tier that changes what we put on the wire rather than which features we enable, and
      monotonicity — correct for the signature *requirement*, since a low claim must not switch
      it off — is wrong for the prefix *choice*, where being walked down would only mean signing
      bare. Accepted for 1.10.2 on likelihood: the App Store offers no downgrade path.

      **The gate covers one of two inbound paths.** `senderEphemeralSignature` lives on
      `RecipientPayload`, so the non-group format has no field for it and `decryptSealed`
      applies no equivalent check. Not a bypass — the prekey store and the identity key sit
      behind identical access control, so anyone able to construct a legacy forward-secret
      bundle can equally sign a group one — but the asymmetry is real and the routing site now
      says so. Note also that the format reflects the *sender's view of the recipient*: a
      current build sends the non-group format to anyone it resolves below `.groupCapable`, so
      no receiver-side check may infer sender capability from the format it arrived in.

      **Invariant: the signature must stay inside the sealed payload — it may never move to
      `SecrecyContext` or any other cleartext field.** ECDSA permits public-key recovery: `(r, s)`
      plus the signed message yields a small candidate set of public keys, each testable against
      the message. Here the signed message is fully reconstructible by a passive observer, because
      it is `"occulta-sender-ephemeral-v1" ‖ ephemeralPublicKey` (`ephemeralSignaturePayload`,
      `Crypto+Manager+GroupEncrypt.swift:267`) and `ephemeralPublicKey` is necessarily cleartext —
      the recipient needs it for ECDH. So a cleartext signature would hand the sender's **identity
      public key** to anyone holding the `.occ` file: sender linkability across bundles today, and
      the identity *private* key to a quantum adversary, since Shor recovers `d` from `Q` and needs
      no signature to do it.

      Placement is correct today — `senderEphemeralSignature` is a field on `RecipientPayload`,
      which is JSON-encoded and AES-GCM sealed into `wrappedPayload` before it reaches the wire
      (`Crypto+Manager+GroupEncrypt.swift:244-248`), so only a recipient who can open their own
      slot ever sees it, and that recipient already holds the sender's identity key from the UWB
      exchange. The field therefore adds no exposure that did not already exist. The rest of the
      bundle is deliberately consistent with this: `SecrecyContext.senderFingerprint` is
      SHA-256(publicKey ‖ 16 random bytes) rather than the key, and `.longTermFallback` sets
      `ephemeralPublicKey` to empty `Data()` for the same stated reason — keeping the sender's
      long-term key out of cleartext AAD.

      **The change to guard against is a plausible one:** hoisting the signature into the
      cleartext header so a receiver can reject forged bundles before unwrapping. That trades a
      verification shortcut for publication of the sender's identity key to every passive
      observer. Reject it, or seal whatever replaces it. New paragraph, added 2026-08-14 after the
      1.10.2 sign-off; the checklist recorded the field's placement (see the inbound-path note
      above) but never why that placement is load-bearing.

- [ ] Messages already sent survive a contact identity-key change
      — **FAIL. Filed as Bug 82**, pre-existing rather than introduced by this release.
      `resolveSenderPublicKey` (`Contact+Manager.swift:1643`) returns only the newest unexpired
      key record, while the model retains the whole history — `update(key:for:)` (`:538`) appends
      on re-exchange and only `reset(identity:)` ever writes `expiredOn`. Three inbound consumers
      depend on that value: the fallback-mode wrapping key, `verifySenderEphemeralSignature`, and
      the `senderProof` HMAC. All three compare against a key that did not exist when the message
      was sealed, so fallback-mode messages become undecryptable outright and forward-secret ones
      fail verification. New item; the checklist did not previously assert this anywhere.

      **Corrected and re-filed 2026-08-15 as Bug 82a/82b.** The wording above and the original
      bug entry both said this triggers on "a contact reinstalling and re-exchanging." It does
      not: `retrievePrivateKey()` (`Key+Manager.swift:163`) returns the existing Enclave key and
      creates one only on `errSecItemNotFound`, and keychain items survive app deletion — so a
      reinstall loses the contact list but not the identity key, and a re-exchange with unchanged
      material appends a record holding identical bytes. The real trigger is an identity-key
      *change*: new hardware, restore to new hardware, in-app Erase All Data, or a device wipe.
      Rarer than claimed, but certain — it is D-19's device-replacement event seen from the
      availability side. The two halves have since been split, because fallback bundles re-open
      indefinitely (so the exposure is every retained bundle, not just unopened ones) while
      forward-secret bundles are single-use by design. See Bug 82 in
      `Docs/Features/Secure Mode/bugs.md`.
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
      — four write sites, all under `pending/<sessionID>/` or `inbound/`. The extension no longer
      touches any app-group-root path at all: `ShareIndex.sqlite` was the one it opened read-only,
      and the mirror was deleted along with the extension's picker (Bug 84).
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
      — all three now live in `ShareSession.load` (`ShareSession.swift`), which zeroes each
      ciphertext buffer immediately after decryption, zeroes accumulated plaintext on any throw,
      and deletes the session directory on failure. `RootView.encryptShareSession` zeroes the
      returned files on every exit and calls `encryptBundle`/`encryptGroupBundle` after the user
      has picked a recipient — which now happens after the PIN, not before it (Bug 84 Part A).
- [x] **EXIF and GPS are actually removed, not merely passed through a function named for it**
      — **was broken from the feature's introduction until 2026-08-16.** `stripEXIF` handed
      `CGImageDestinationAddImageFromSource` an empty properties dictionary, but that argument is
      a set of *overrides* onto the source's metadata: empty means override nothing, so capture
      location and time were copied verbatim into every shared photo. Removal requires naming
      each dictionary with `kCFNull`, which `ShareSession.stripEXIF` now does for Exif, ExifAux,
      GPS, IPTC, TIFF, and MakerApple, carrying orientation over explicitly. Covered by
      `ShareSessionTests.load_stripsEXIFFromImages` and
      `load_preservesOrientationThroughTheStrip`, with `exifFixture_carriesMetadata` guarding the
      fixture. **Any photo shared through the extension before this date carries its original
      location to whoever received it; the bundles are already delivered and cannot be recalled.**
- [x] Session directory (`pending/<sessionID>/`) is deleted immediately after
      the flow completes — on both success and failure paths
      — `encryptShareSession`'s `defer` covers success, throw, and the picker's Cancel;
      `ShareSession.load` additionally deletes on its own failures, so the guarantee does not
      depend on caller discipline.
- [x] On app launch, any `pending/` directories surviving from a previous crash are swept and
      deleted before processing any new session
      — `cleanupPendingSessions()` on `scenePhase == .active` (`OccultaApp.swift:348`), which
      fires on launch and on every foreground return. Sessions with no manifest, an unreadable
      manifest, or one older than an hour are removed
      (`ShareSession.sweep`). Note the comment at `:156` calls manifest-less
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
      `enableShamirShardSharing: true`. `signature: false` confirmed as the intended shipping
      value for 1.10.2 (2026-08-13) — it is the one flag whose value is not self-evident from
      the code, so it is recorded rather than re-derived at each release.
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
      of those being §7.2, deliberately left in place for this release. (Those five are gone as
      of `release/v1.10.3`; the sentence records the 1.10.2 archive as inspected. See §7.)

## 7. Dependency & Supply Chain

- [x] No third-party dependencies (confirmed: no CocoaPods, SPM, Carthage)
      — **was FAIL for 1.10.2, fixed on `release/v1.10.3` (2026-08-14, after the 1.10.2
      sign-off).** 1.10.2 shipped with an SPM dependency: `apple/swift-crypto` (pinned 4.2.0),
      pulling `apple/swift-asn1` (1.5.1), with three products linked — `Crypto`, `CryptoExtras`,
      `_CryptoExtras`. All three product dependencies, the package reference, and
      `Package.resolved` are now removed; `grep` over `Occulta.xcodeproj/` returns no
      `XCRemoteSwiftPackageReference`, `XCSwiftPackageProductDependency`, or `packageReferences`.
      The project has no package dependencies of any kind.
- [x] All crypto uses Apple frameworks only (`CryptoKit`, `Security.framework`) — no vendored
      crypto code
      — **was FAIL for 1.10.2, fixed on `release/v1.10.3` (2026-08-14).** 1.10.2 shipped five
      swift-crypto resource bundles inside the app, including
      `swift-crypto_CCryptoBoringSSL.bundle` and `swift-crypto_CryptoBoringWrapper.bundle` —
      vendored BoringSSL. The crypto *in use* was already Apple-framework-only, so what failed
      was the artifact, not the cipher suite.

      **Why nothing depended on it, established before removal.** `import Crypto` occurred in
      exactly one file (`Crypto+Manager.swift:14`), directly under `import CryptoKit`. On Apple
      platforms that import is a no-op: swift-crypto's `Crypto` target excludes every BoringSSL
      dependency via `.when(platforms:)` gates naming only linux/android/windows/wasi/openbsd
      (`Package.swift:55–74`), and every file under `Sources/Crypto/` compiles to
      `@_exported import CryptoKit` under `#if CRYPTO_IN_SWIFTPM && !CRYPTO_IN_SWIFTPM_FORCE_BUILD_API`.
      So `import Crypto` on iOS resolved to `import CryptoKit`, which is why deleting it changes
      nothing — the symbols in that file (`AES.GCM`, `HKDF`, `SHA256`, `P256`) were CryptoKit's
      throughout. A repository-wide search found no swift-crypto-only API (`_RSA`, AES-GCM-SIV,
      PBKDF2, scrypt, ARC, AES.CBC/CTR, ASN1 types) and no module-qualified `Crypto.*` usage; the
      DER signatures the code handles come from `SecKeyCreateSignature`, not swift-asn1. ML-KEM
      comes from CryptoKit's SE-backed `MLKEM1024`, gated on iOS 26 in `PQProvider.swift`.

      **The bundles came from `CryptoExtras`/`_CryptoExtras`, not `Crypto`.** Those two are
      BoringSSL-backed on every platform, were linked into the app target, and were imported by
      zero files — pure link-time weight. Removing them required no source change at all;
      removing `Crypto` cost the one import line.

      **Verified** by re-archiving (Release, `generic/platform=iOS`, `CODE_SIGNING_ALLOWED=NO`):
      zero `*.bundle` anywhere in the archive (was five), zero paths matching `*crypto*` or
      `*boring*`, zero BoringSSL symbols under `nm -a` on the app binary, and `otool -L` reporting
      `/System/Library/Frameworks/CryptoKit.framework/CryptoKit` as the only crypto link.
      `Occulta.app/` now holds exactly the §6 list minus those five bundles.

      Not re-run for this change: the test suite. No test file imports `Crypto`, and the archive
      compiles the app and both extensions — but that is reasoning, not a run, and §8 needs an
      Enclave host regardless.
- [x] Xcode and macOS SDK versions are up to date for the release build
      — Xcode 26.2 (17C52), iOS SDK 26.2, macOS 26.5.2. `SWIFT_VERSION = 5.0` (language mode,
      not toolchain). `IPHONEOS_DEPLOYMENT_TARGET = 18.6` uniformly across all ten
      configurations — note CLAUDE.md still says iOS 16.0+, which is stale by two major
      versions and worth correcting, though nothing depends on it.

## 8. Testing Gate

**A green CI run does not satisfy this section.** GitHub-hosted macOS runners are VMs with no
Secure Enclave, so 260 of the suite's 738 tests — including every prekey-isolation guard — skip
there. CI
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

- [x] **Zero failures.** 728 Swift Testing tests across 164 suites, plus 36 XCTest cases —
      758 passed, 0 failed, 6 skipped. Run serially (`-parallel-testing-enabled NO`).
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
3. ~~Prekey survives a rejected group bundle~~ — **fixed.** Consumed at the moment the slot
   opens, covering all three throw sites and any added later. Accepts a known cost: a rejected
   bundle now burns a prekey. See §2.2.
4. ~~Unused swift-crypto dependency ships vendored BoringSSL~~ (§7.1, §7.2) — **accepted for
   1.10.2, then removed on `release/v1.10.3` (2026-08-14), which is the "revisit before the next
   tag" this item asked for.** All three product dependencies, the package reference, and
   `Package.resolved` are gone; the one `import Crypto` was an alias for CryptoKit and the
   BoringSSL bundles came from the two `CryptoExtras` products, which nothing imported. Verified
   against a fresh archive: zero bundles, zero BoringSSL symbols, CryptoKit the only crypto link.
5. ~~`senderEphemeralSignature` has no domain-separation prefix~~ — **fixed**, behind the
   `.prefixedSenderSignatureCapable` tier so 1.10.0/1.10.1 recipients keep receiving messages.
   The bare verification arm is transitional; remove it once those versions are gone. See §3.6.
6. **Messages do not survive a contact identity-key change** (§3, Bug 82) — pre-existing,
   availability rather than confidentiality. Re-filed 2026-08-15 as 82a/82b; the sentence this
   item carried at sign-off — that fixing it "confines any consume-on-rejection remedy to
   genuinely forged bundles" — applies only to **82b**, the forward-secret half, which is the one
   being deferred. So that reasoning stays incomplete for now: a contact replacing their device
   still burns a prekey on an unopened FS bundle with no attacker involved. **82a**, the fallback
   half, is the one targeted for v1.11.0 — it is the larger exposure (retained bundles, not just
   unopened ones) and the cheaper fix (no prekey interaction at all), but it does not close this
   §2.2 gap.
7. ~~Stale item wordings to correct so future passes measure the right thing: §1.2, §1.5, §2.5,
   §3.2, §5.1, §6.2, §8's skip rule.~~ **Addressed 2026-08-15** — replacement wording for all seven
   is in the "Correction block" below the sign-off, appended rather than edited in place so the
   1.10.2 sign-off keeps attesting to the text that was signed. Adopt at the next pass. The two
   CLAUDE.md clauses this item also named — "no external package manager" and "iOS 16.0+" — are
   both gone; neither string is in the file, and its Build & Test section now records the 18.6
   target and the removed dependency.

Every item now carries a result. Two smaller things recorded in place rather than raised here:
`deleteAllKeys(for:)` is best-effort with no signal on failure (§2.4), and contact-identifier
encryption falls open to the raw UUID if key derivation fails (§4.1).

---

## Correction block — item wordings, appended 2026-08-15

Blocker 7 above lists seven items whose **wording** is wrong, in the specific sense that a future
pass following the text literally would measure the wrong property and record a FAIL against
correct code. The replacement wording for each is given here rather than edited into the items in
place, so the 1.10.2 sign-off keeps attesting to exactly the text that was signed. **Adopt these at
the next pass**; from that point the items above are superseded by this block.

Nothing here changes a result. Every item is a re-description of a property already verified; the
evidence lines attached to each item above remain valid as written.

**§1.2 — AAD.** Replace *"AAD is always `version ∥ sorted SecrecyContext fields` — no call site
omits it"* with:

> Every **bundle** encryption binds `version ∥ sorted SecrecyContext fields` as AAD, via
> `computeAdditionalAuthentication(version:secrecy:)`. Seals outside the bundle/transport path —
> the PIN verifier sentinel, `ShareIndexKeyManager`, and `SecureMode+LayerStore` — are separate key
> contexts with no `SecrecyContext` to bind and are out of scope for this item.

Rationale: the rule is a bundle-transport rule. Stated universally it makes three correct, unrelated
key contexts read as violations.

**§1.5 — Hybrid combiner.** Replace *"P-256 shared secret XOR'd with both ML-KEM secrets before
HKDF, not after"* with:

> The hybrid IKM is the **concatenation** `ECDH ‖ sorted(kem₁, kem₂)`, HKDF'd with the ECDH-derived
> salt, with the two ML-KEM secrets in canonical sorted order so both sides agree on ordering.

Rationale: the item as written describes a construction that would be *wrong*. XOR into a
fixed-width value discards entropy; concatenation is the correct KEM combiner. The code is right and
the item was wrong.

**§2.5 — `PortingManager`.** Delete the item. No such type exists anywhere in the repository. The
property it guarded still holds by construction and is worth keeping under a name that exists:

> No code path exports an SE private key. Every `SecKeyCopyExternalRepresentation` call site
> extracts a **public** key (`PrekeyManager.swift:70`, `ShareIndexKeyManager.swift:147`, and
> `TestKeyManager`'s in-memory pairs).

**§3.2 — Peer identity.** Replace *"MCSession peer identity is validated before accepting key
exchange data"* with:

> Key exchange is gated by **physical proximity plus out-of-band confirmation**, not by transport
> authentication: a peer's discovery token must range at ≤ 0.25 m before any identity is sent
> (`Exchange+Manager.swift:638`), `guard self.exchangeStatus == nil` allows the protocol to start
> exactly once, and both sides compare diceware words derived from the completed shared secret
> (`KeyExchange.swift:236`). MultipeerConnectivity authenticates nobody — `securityIdentity: nil`,
> all invitations accepted, no `didReceiveCertificate` — and is not relied on to.

Rationale: as written the item asserts a check that does not exist, so it can only ever be recorded
FAIL. The residual risk it should prompt a reviewer to re-examine is the ranging race, which is
tracked in §B of `OPEN_LIMITATIONS.md`. If `didReceiveCertificate` is ever implemented, restore the
original item alongside this one rather than replacing it.

**§5.1 — Share Extension types.** Replace *"Extension matches on UTI
`com.github.aibo-cora.occulta` and `.occ` path extension fallback — no other types accepted"* with:

> **Inbound** (`.occ` intake): `looksLikeOCC` (`ShareViewController.swift:410`) matches exactly the
> `com.github.aibo-cora.occulta` UTI and the `.occ` path extension, and nothing else.
> **Outbound** (encrypt-for-contact, the extension's primary purpose): the activation rule
> deliberately accepts any file and any image, up to 20 each (`ShareExtension/Info.plist`).

Rationale: the item claims a restriction the extension does not have **and should not have** — the
broad activation rule is the feature.

**§6.2 — Debug symbols.** Replace *"`Strip Debug Symbols During Copy` = YES in Release"* with:

> The archived binary carries **no debug map** — `nm -a` reports zero `OSO`/`SO`/`FUN` entries for
> `Occulta` and for `ShareExtension.appex` — and full `.dSYM`s are produced for all targets.

Rationale: `COPY_PHASE_STRIP` is a legacy setting governing files copied by a Copy Files phase, not
the product. It is `NO`, and the product is stripped anyway. Assert the property, which is what
matters and what is measurable, not the setting.

**§8 — Skip rule.** Replace *"Zero skips, excluding `KeychainMigrationSETests`"* with:

> **Exactly 6 skips, and all six are `KeychainMigrationSETests`.** Any other skip means the host
> lacked a Secure Enclave and the run does not count toward this gate.

Rationale: those six throw `XCTSkip` from `setUpWithError` behind a compile-time
`#if targetEnvironment(simulator)`, so they cannot run on any host this gate permits — only a
physical device runs them. "Zero skips" is therefore unachievable rather than merely unmet.

**The exclusion is permanent, and the obvious alternative does not work — tried and reverted
2026-08-15.** Swapping the compile-time gate for a runtime `.enabled(if: secureEnclaveAvailable())`
looks right, because a bare-metal Simulator genuinely does reach the Enclave. It fails on a
distinction the predicate cannot see: Enclave *key creation* works in the Simulator (an SE-key probe
returns true, and `testKeyCreatedWithAccessGroupIsDiscoverable` passes), but `SecItemUpdate` cannot
add `kSecAttrAccessGroup` to an SE-protected key there, returning **-25303 `errSecNoSuchAttr`** —
and that update is the entire subject of the suite. The runtime gate therefore converts six honest
skips into two failures reading *"the migration strategy is unviable"*. Enclave availability is not
the predicate; Simulator keychain fidelity is, and nothing probes it short of the assertion itself.
The gate now carries a note saying so.

**Not in this block, because it is a result rather than a wording problem:** §3.7 (messages
surviving a contact identity-key change) remains a genuine FAIL, tracked as Bug 82a/82b.

---

**Signed off by:** Yura Filatov — recorded 2026-08-14 on the release owner's instruction
**Release version:** 1.10.2 (build 3)
**Date:** 2026-08-14
**Full-suite result:** 774 passed / 0 failed / 6 skipped — 738 Swift Testing tests in 166
suites plus 36 XCTest cases; all six skips are `KeychainMigrationSETests` (see §8)
**Host used:** Apple Silicon, iPhone 17 Pro Simulator, bare metal (Secure Enclave available)
**Archive inspected:** Release, `generic/platform=iOS`, `CODE_SIGNING_ALLOWED=NO`
**Verification performed by:** an agent-run pass over this checklist during a working session
with the release owner, who took each accept/defer decision recorded below. Per-item evidence is
attached to each item above rather than summarised here.

### Scope of this sign-off — read before relying on it

This attests that every item carries a **recorded result**, not that every item passes. 45 of 55
are ticked; the other 10 are stale wordings, accepted limitations, or deferred bugs, each with a
decision written down. There is no item in the "we did not look" state, which is what the earlier
version of this block would have been signed over.

**Post-sign-off, 2026-08-14 (`release/v1.10.3`):** §7.1 and §7.2 have since been fixed and ticked,
so the current count reads 47 of 55. The numbers above are left as the record of what was signed
for 1.10.2 — which did ship the dependency — rather than backdated. Nothing else in this sign-off
is affected: the change removes an unused package and touches no crypto path, and it was verified
against its own fresh archive, not the one named above.

Three conditions of the gate are **not** met, knowingly:

1. **The signed artifact was never inspected.** The archive above was built with
   `CODE_SIGNING_ALLOWED=NO`. That is sound for bundle contents and debug symbols — both were
   checked — but it is not the binary that ships. Re-run the §6 checks against the signed build
   before submitting.
2. **§8's "zero skips" is met only under an exclusion.** Six `KeychainMigrationSETests` skip on a
   compile-time `#if targetEnvironment(simulator)` gate that never consults
   `secureEnclaveAvailable()`, so they cannot run on any host this gate permits. Any *other* skip
   invalidates the run.
3. **No second human read the code.** [PR #73](https://github.com/aibo-cora/occulta/pull/73) is
   unreviewed. Most of the changeset was written and then reviewed within the same session, which
   caught real defects — the unconsumed prekey, the stranded drafts, two duress oracles — but is
   not independent review and should not be recorded as such.

Also relevant to how much the green test number is worth: **260 of 738 tests are Enclave-gated**
and skip on CI, and ~113 more still use the legacy `print("⚠︎ Skipping"); return` form, which
reports as *passed*. See CLAUDE.md.

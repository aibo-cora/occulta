# Occulta — Security audit of the local encryption keys

**Date:** 2026-11-10 to 2026-11-11
**Commit:** `87d9bf11d4d8190f19da0cad8ac12aaaba4a6bb3` (the v2.0.1 line; worktree cut from `v2.0.1/version-bump`). Every file:line below refers to this commit.
**Scope:** the keys that protect data at rest on the device. A subsystem audit, not a diff.
**Method:** the `occulta-security-audit` skill (Cloudflare's security-audit method with Occulta's threat model), `quick` profile: one hunter wave, independent verification, one final coverage critic.
**Run status:** `incomplete`. Eight units the critic named were not hunted, and two units were hunted shallowly. See "Coverage" for what that leaves open.

No production code was changed, nothing was committed, and nothing was run on a phone.

## Summary

The core of the Bug 171 work holds up. Every Enclave-bound key needs the Enclave key, the tier's Keychain secret and, on iOS 26+, the Enclave's ML-KEM secret. No derivation was found whose inputs a holder of public data can reproduce. The reseal inventory matches the schema, the launch ordering is sound, and the vault's per-entry keys are sealed only under the gated vault key. The app has no third-party dependency.

The findings are around the keys, not in them: what is left on disk after data is deleted or re-keyed, and what the process does after a wipe.

| # | Lead | Proposed severity | Bug |
|---|---|---|---|
| 1 | `PRAGMA secure_delete` is set on a helper connection and does not reach SwiftData's own connection, so deleted rows stay in the store file | high | 210 |
| 2 | A Secure Mode layer file written by releases up to 1.10.3 stays in the App Group, holding hidden contacts in plaintext under a key derived from a public point | critical on affected devices, low elsewhere | 211 |
| 3 | After Erase All Data the process cannot derive its local keys until relaunch, so new contact data is silently dropped and the identifier is stored in the clear | medium | 212 |
| 4 | Staged share files are not bound to their session or manifest, so a sealed file from an earlier share can be substituted | low | 213 |
| 5 | No default data-protection entitlement; store sidecars and the Drafts directory can sit at the default protection class | low | 214 |

All five are `needs_validation`: this audit reads source and does not run the app. Leads 1 and 2 have supporting evidence from outside the app (see each). The method assigns no severity to a lead, so the severities are proposals on the scale in the skill's threat model.

## Deviations from the method

- **Recon.** Agents 1a–1d were replaced by an architecture note written from the parent's own reading. Recon 1e (known limitations) ran.
- **Usage limits.** The limit stopped all six hunters once and the verifier once. Each was resumed from its saved state, not restarted.
- **Lost working files.** The scratchpad was emptied by a temp cleaner overnight, after five of six hunter results had been read. `coverage-ledger.json` (validated, 10 of 10 units, after each ledger change) and the hunter result files are gone, so this directory holds no `findings.json` or ledger JSON and the vendored validators were not run on a final state. The ledger below is rebuilt from the results as read. The sixth hunter rewrote its result on request.
- **Verification.** The two hunter candidates were verified by the parent, which did not hunt them. The three leads the parent found were verified by a separate Sonnet agent. Lead 1 came from a hunter's hardening note and was promoted after the parent's own checks.
- **Models.** Hunters for derivations, reseal, share staging and the vault ran on Opus; the artefacts and stored-keys hunters, the verifier and the critic on Sonnet. Nine agents in all (1 recon, 6 hunters, 1 verifier, 1 critic), seven of them resumed once after a usage limit.
- **Two hunters were shallow.** `hunter-artefacts` said so in its own report: it did not compare every Keychain item against the wipe or check item timestamps and sizes across installs. `hunter-derive` covered the wipe-versus-Keychain comparison instead.

## Coverage

### Units hunted

| # | Surface | Boundary | Attack class | Hunter | Result |
|---|---|---|---|---|---|
| 1 | Key derivations in `Manager.Key`: legacy, Enclave-bound, hybrid; tier secrets; tier PQ records | Enclave, biometric and tier-secret binding of every derived key | Cryptography and secrets | derive | covered, no candidate |
| 2 | Keychain and Enclave items: accessibility, access control, access group, creation races, `deleteAllKeys()`, key bytes in memory | Keychain item attributes | Credential-store and local-secret boundary mismatch | derive | covered, no candidate |
| 3 | Key reseal, hybrid upgrade, PQ migration, launch ordering | Sealed-field integrity across aborted and repeated passes | Migration default and ownership confusion | reseal | covered, no candidate; one hardening note became lead 1 |
| 4 | Share staging key and staged files in the App Group | App Group and shared-keychain secrecy; session validation | Credential-store boundary mismatch; IPC peer authentication | share | candidate: lead 4 |
| 5 | Vault key use, per-entry keys, vault epoch and rewrap, backup key, custody and return buffer | Biometric gate and Enclave binding of the vault key | Cryptography and secrets | vault | covered, no candidate |
| 6 | Vault backup export and restore (`.occbak`), Shamir | Depth scope and authority of restored key material | Import and restore authority expansion | vault | covered, no candidate |
| 7 | Persistent artefacts: file protection, backup exclusion, Erase All Data, logs | Forensic rules | Logs and diagnostics; retention | artefacts (shallow) | candidate: lead 2. Leads 1, 3 and 5 came from the parent |
| 8 | Secure Mode PIN key, verifiers, filler | Offline guessing resistance, depth-count secrecy | Cryptography and secrets | artefacts (shallow) | no candidate |
| 9 | Other stored private keys: prekeys, pairing slot keys, card keys, ML-KEM blobs, attachment keys | Each sealed under an Enclave-bound key or held in the Enclave | Cryptography and secrets | stored | covered, no candidate |
| 10 | CI workflow, package manifest, project file, entitlements | No third-party dependencies; workflow permissions | Supply chain | stored | covered, hardening notes only |

### Deferred (`quick_profile_final_critic`)

The critic's verdict was "partial". These were not hunted in this run:

1. Passphrase and Diceware-derived keys (`Occulta/Services/Passphrase+Manager.swift`): KDF strength, salt storage, pasteboard use.
2. Draft storage (`Message+Draft.swift`, `DraftStore.swift`, `ComposeViewModel.swift`): which key seals drafts, depth separation, wipe.
3. Identity key handling and the key fields on `Identity`, `Contact` and `Group` models.
4. Streaming attachment encryption (`Attachment+Manager.swift`, `StreamedReceive.swift`): chunk keys, temp files, cleanup on abort.
5. Identity challenge crypto and ledger persistence.
6. Forward-secrecy and group derivations (overlaps the wire-format scope; low priority for at-rest keys).
7. `Vault+Manager+Diagnostic.swift` (debug-only by the derivations hunter's reading) and `BackupEncryptionKey+Model.swift`.
8. `Tools/OccultaMeasure` and `OccultaPreview`: confirm neither ships key code in the app target.

Second looks the critic asked for: an end-to-end Erase All Data inventory (every container against what the wipe deletes), and PIN verifier indistinguishability by size, existence and timing across depths.

## Leads

### 1. `PRAGMA secure_delete` does not reach SwiftData's connection (Bug 210, proposed high)

**What the code does.** `OccultaApp.applySecureDeletePragma` opens a short-lived SQLite connection, runs `PRAGMA secure_delete = ON` and closes it (`Occulta/App/OccultaApp.swift:169-174`). Its comment says the setting "is stored in the database header and persists across all future connections to the same file — including SwiftData's own connection" (`:160-163`).

**Why that is wrong.** SQLite's `secure_delete` is a property of a connection. Nothing is written to the file.

**What rests on it.** `forensic-trace-avoidance.md` lists it as control S2, rated High and marked done (`:79`, `:113-114`, `:149`). `bugs.md:5549` says "Page hygiene needed no new work". Erase All Data (`Occulta/Services/Manager+App.swift:40-42`), the prekey scrub (`Contact+Manager+Prekeys.swift:201-205`), the card-key clear (`ContactManager+Cards.swift:160`) and the duress draft purge all delete rows, checkpoint the WAL and rely on the freed pages being zeroed. The checkpoint works, because it is its own connection's action. The zeroing is the part in question.

**Evidence gathered outside the app** (the Mac's system SQLite 3.54.0 and Core Data; not Occulta code, not a Simulator run):

- One connection sets `secure_delete = ON` and closes. A second connection to the same file reads `2`, which is Apple's default, FAST. FAST leaves freed pages as they were.
- A standalone Core Data program created a store, set the pragma through a helper connection exactly as the app does, inserted 60 rows with 9 KB blobs, deleted them through Core Data and ran a `TRUNCATE` checkpoint. 38,961 of 41,460 marker copies were still in the store file. Without the helper pragma the number was 38,835, so the pragma made no difference. With 300-byte blobs, 768 of 1,440 remained.
- As a control, deleting on a connection that has `secure_delete = ON` itself left 0 copies.

**Impact.** A deleted row's content stays in the store file until SQLite reuses the page. Most of it is ciphertext under the local DB key, which is still on the device, so an examiner who can use the device's keys (Bug 119) recovers contacts, drafts and records the owner deleted, including real-depth drafts purged on a duress unlock. Plaintext columns stay readable with no key. After Erase All Data the keys are gone, so only plaintext columns and row shapes remain. Retired prekey and card keys are Enclave blobs kept inside sealed columns, so the forward-secrecy claim that overwriting the column deletes the key depends on the same zeroing. The reseal hunter found that a same-size in-place update leaves no old bytes, so the exposure is deletions and shrinking values, not every write.

**Not settled by source.** Whether SwiftData on iOS sets `secure_delete` on its own connection. macOS Core Data does not, by the test above.

**Fix proposal.** SwiftData exposes no pragma option, so scrub from the helper connection instead of relying on the setting: run `VACUUM` in `checkpointStore()` after the `TRUNCATE` checkpoint and once at launch before the container opens. `VACUUM` rewrites the file without free pages. Check under test that it gets its lock while SwiftData holds the store open. Then correct the comment at `OccultaApp.swift:150-168` and S2 in `forensic-trace-avoidance.md`. The plain-SQLite store decided for 2.1.0 can set the pragma on its own connection, which settles this for whatever moves to it.

**Evidence file.** `secure-delete-check.swift` in this directory is the standalone Core Data program. Build it with `swiftc -O` on a Mac; it touches no Occulta code.

**Test plan.** Open a file-backed SwiftData container in a temp directory, apply the app's pragma helper, insert rows whose sealed column carries a known marker of about 9 KB, delete them, call `checkpointStore()`, then scan the store and `-wal` for the marker. The test fails today if the lead holds. It needs no key material, so it runs on CI.

### 2. A retired Secure Mode layer file stays in the App Group (Bug 211, proposed critical on affected devices)

**History.** Releases 1.9.2 to 1.10.3 shipped with the `secureMode` flag on and wrote `group.com.occulta.shared/blobs/<uuid>.occbak` at every launch (`git show release/v1.10.3:Occulta/Features/SecureMode/SecureMode+LayerStore.swift`, header `:5-25`, `writeNoOpFile` `:359-372`). The file is 32 AES-GCM slots under `HKDF(deriveSecureModeKey(), "layer-store-key")` (`:155-156`). No PIN and no other secret goes into that key. `deriveSecureModeKey()` is ECDH against the generator, a function of the PIN Enclave key's public point (Bug 171; `Occulta/Services/Key+Manager.swift:49-54`).

**Content.** With Secure Mode inactive every slot is sealed random bytes. With Secure Mode active and sensitive contacts present, one slot holds a `LayerPayload`: each hidden contact as a plaintext `Contact.Draft` (names, numbers, emails, addresses, notes, images, key material), the decrypted signed attributes and depths (`:40-72` in that file).

**What happened to it.** Commit `1bf5c5d2` (2026-09-10, "Removal Stage 2", first shipped in 1.11.0) deleted the code that reads and writes the file. Nothing deletes the file:

- At this commit no code touches the `blobs` directory. The only mentions are a comment (`Occulta/Features/SecureMode/SecureMode+LayerStoreBackend.swift:54`) and the reseal inventory, which lists it as a retired leftover that "nothing reads" (`Occulta/Services/KeyReseal+Inventory.swift:350-354`).
- The key reseal does not move it, so it stays under the legacy key while the rows it duplicates moved to Enclave-bound keys.
- `ShareSession.removeAll`, which Erase All Data calls, removes only `pending`, `inbound` and the legacy index (`Occulta/Features/ShareExtension/ShareSession.swift:333-338`). After a wipe the file stays; the PIN Enclave key is deleted, so the content is then open only to someone who already holds the public point.
- `forensic-trace-avoidance.md:32` says "There is no blob". On an upgraded device there is.

**Impact.** On a device that upgraded from 1.9.2–1.10.3 with Secure Mode active and hidden contacts, an examiner who holds or can use the PIN key's public point reads those contacts as they were at the last launch of the old build, including contacts deleted since. A real slot that decrypts to JSON also shows that Secure Mode was in use. This is Bug 171's "ciphertext under the legacy key" on the device itself, in a file the fix did not reach. On every other upgraded device the file is 32 random slots with a frozen modification date, a weak trace.

**Not settled by source.** Whether devices in that state exist, and what the file holds on them. The dev-only `cache/` directory (the backup-key array between 2026-09-08 and its removal) is deleted by its migration at unlock (`Vault+Manager+Backup.swift:655-689`), except a wrong-size file, which is left for ever (`:658-662`).

**Fix proposal.** Delete the `blobs` directory at launch, in `LaunchSequence`, at every depth and before any PIN, and add `blobs` and `cache` to `ShareSession.removeAll`. Correct `forensic-trace-avoidance.md:32` and the inventory entry. One point for the owner: the project's habit is to keep legacy security artefacts so a downgraded build fails closed. Here a 1.10.3 build that finds no file writes a fresh no-op one, which is the same state as a device that never used Secure Mode, and Bug 168 already accepts the cost of downgrades.

**Test plan.** Plant `blobs/x.occbak` and `cache/y.occbak` in a temp container. Run the launch cleanup and, separately, `Manager.App.eraseAllData(stagingContainer:)` with that container. Assert neither directory survives. Runs anywhere. The device check is the owner's: inspect the App Group container of a phone that upgraded from 1.10.x.

### 3. After Erase All Data the process cannot derive its local keys until relaunch (Bug 212, proposed medium)

**Trace.**

- The Settings button calls `eraseAllData()` and the app carries on without relaunching (`Occulta/UI/Tabs/Settings/Settings.swift:176`; `bugs.md:11249` says so too).
- The wipe deletes `r_U`, `r_B` and the tier PQ records (`Key+Manager.swift:1190-1207`) and the `AppLayerConfig` row with both epochs (`Occulta/Features/Vault/Vault+Manager.swift:441-464`).
- `Manager.Ambient.tierUKeys` is set only by `LaunchSequence` (`LaunchSequence.swift:94`, `:112`), so it stays `.enclaveBound`.
- `enclaveBoundKey(.localDB)` returns nil when the tier secret is missing and creates nothing (`Key+Manager.swift:1350-1359`), so `Manager.Crypto().encrypt(data:)` returns nil (`Occulta/Services/Crypto+Manager.swift:65-72`).
- Nothing recreates `r_U` in the same process: `createTierSecretIfAbsent(.deviceUnlock)` is called only from the launch bootstrap (`KeyReseal+Run.swift:72`).

**Result.** A contact created after the wipe and before a relaunch is stored with its identifier as the raw UUID (`?? rawIdentifier`, `Occulta/Services/Contact+Manager.swift:395`), every sealed field empty, and `encryptionScheme` stamped v2 although nothing was sealed. The next launch creates a fresh `r_U`; the fields are already lost. Someone who wipes the phone and then exchanges keys in person, without closing the app, loses that contact's details silently.

**The vault in the same state.** `unlock` finds no epoch and leaves `Manager.Ambient.vaultKeys` as it was (`Vault+Manager.swift:263-271`). If the vault was not opened earlier in this process, that is `.legacy`: the legacy path creates a new vault Enclave key and `r_B` (`Key+Manager.swift:913-917`), and entries added then are sealed under the key that is a function of the public point, until the first unlock after the next launch rewraps them. If it was opened earlier, the key is nil and the vault stays locked.

**Correction from verification.** This applies only when the process was `.enclaveBound` at the wipe, which is the normal state once the reseal has completed. A process still on the legacy keys recreates its secret and keeps working.

**Known?** No. Bug 128's follow-up covers only the vault row and filler rows after a wipe. `SECURITY_CHECKLIST.md:351-353` notes the `?? rawIdentifier` fall-open in general. Whether the key-exchange and import paths drop key material the same way was not traced.

**Fix proposal.** End `eraseAllData` by running the same bootstrap a fresh install's launch runs (`LaunchSequence.run` on the emptied store), so `r_U`, the records and the config row exist again and the process state is decided from them. The rule that the state never changes mid-session exists so a key derived before a switch cannot write old-form ciphertext; after a wipe there is no data for that to apply to. Make `Contact+Manager.swift:395` throw instead of storing the raw identifier.

**Test plan.** With `.ambientTestKeyManager` on a store that has an epoch: run `eraseAllData` through its seams, then create a contact in the same process and read it back through a fresh context. Assert the fields round-trip and the stored identifier is not the raw UUID. Fails today.

### 4. Staged share files are not bound to their session (Bug 213, proposed low)

**Trace.** The extension seals each staged file as an `.eatt` under the long-lived share staging key and seals the manifest separately. `ShareManifest.FileEntry` holds only `filename`, `uti` and `fileExtension` (`Occulta/Features/ShareExtension/ShareManifest.swift:21-28`). The manifest is sealed with no authenticated data (`ShareStagingKeyManager.swift:590-597`). `ShareSession.staged` checks freshness on the manifest's `createdAt` only and accepts any file whose header opens under any staging key (`ShareSession.swift:104-145`, `:166-171`). The staging key lives until Erase All Data.

**Impact.** Someone who can write the App Group container but cannot use the key can copy a sealed file kept from an earlier share into a new session as `0.tmp`, or swap files between sessions. The app then encrypts the substituted content for whichever recipient the user picks, and the picker does not show the content. The attacker is the one Bug 171's open item 7 already assumes (write access to the App Group). This path works with files sealed under the current key, so it does not end when the legacy fallback is removed.

**Fix proposal.** Record each file's header MAC (or salt and plaintext size) in its manifest entry and compare before opening, and put the session id in the manifest's authenticated data.

**Test plan.** In `ShareSessionTests` with the in-memory key: stage session A with bytes "A" and session B with bytes "B", copy `A/0.tmp` over `B/0.tmp`, load B. Today it returns "A"; the fix must make it throw. A second case moves A's manifest into a fresh directory. Runs anywhere.

### 5. No default data-protection entitlement (Bug 214, proposed low)

**Trace.** Neither entitlements file has `com.apple.developer.default-data-protection`, and the project file has no data-protection setting. The store is created by `ModelContainer(...)` and stamped `.complete` afterwards with `try?` (`OccultaApp.swift:69-80`). The `-wal` and `-shm` files SQLite recreates are re-stamped only from a SwiftUI `.onReceive` of a save notification (`:373-377`, `:1272-1278`). Between a sidecar's recreation and the next save it has the default class, and a failed stamp is silent. `Application Support/Drafts/<id>/` is created and filled with no explicit class (`Occulta/UI/Tabs/Contacts/v2/DraftStore.swift:199-210`).

**Impact.** Limited: field values are sealed by the app, so what a weaker class exposes while the phone is locked after first unlock is schema, row counts, sizes and plaintext columns. The S3/S4 controls are recorded as done; the window, the ignored failures and the missing entitlement are not. `forensic-trace-avoidance.md:120` names the default class as `completeUnlessOpen`; the iOS default for app files is complete-until-first-authentication. Either is weaker than `.complete`.

**Fix proposal.** Add the entitlement with `NSFileProtectionComplete` to both targets, so every file is born at the right class, and keep the explicit stamps. The app already assumes an unlocked phone for every store access.

**Test plan.** A Simulator test cannot show protection classes reliably. Check on a device with no real data: create the store, force a checkpoint, read `URLResourceValues.fileProtection` for the three files and the Drafts directory.

## Hardening notes

Each was checked against source. None is filed as a bug.

1. **A failed key deletion is silent.** `eraseAllData` discards the `Bool` from `deleteAllKeys()` and the button uses `try?` (`Manager+App.swift:47`, `Settings.swift:176`). Data is gone and the user is not told that a key stayed.
2. **Keychain queries pin no access group.** `Manager.Key` finds tier secrets and records by account alone (`Key+Manager.swift:1442-1465`, `:1535-1554`, `:1626-1633`, `:1213-1221`), so they also match items in `group.com.occulta.shared`. Only Occulta's own extension can write there, and it uses distinct accounts, so there is no collision today. Pin `kSecAttrAccessGroup` or a service string.
3. **The vault tier's ML-KEM key has no biometric gate.** It is created with `.privateKeyUsage` only (`OccultaCore/Sources/OccultaCore/PostQuantumProvider.swift:156-168`). The vault key still needs the gated Enclave key and gated `r_B`, so the gate holds. Giving the tier B key the vault's access control would gate all three terms.
4. **A missing Enclave key is recreated silently.** `retrieveLocalDBPrivateKey`, `retrieveVaultPrivateKey` and `retrieveShardCustodyPrivateKey` create a key when the tag is absent (`Key+Manager.swift:673-698`, `:899-925`, `:1004-`). With `r` and the record present, that yields a different key and unreadable data with no error. The comment at `:1342-1343` promises "nothing created" only for a missing secret or record.
5. **Key bytes are never zeroed.** `r_U`, `r_B`, the ECDH output, the ML-KEM secret and the HKDF input live in `Data` and `[UInt8]` buffers that are released, not cleared (`Key+Manager.swift:1408-1415`, `:1482-1490`). `MemoryGuard.swift` checks available memory; it is not zeroization.
6. **An unreadable vault epoch keeps the previous mode.** After launch that is `.legacy`, the key that is a function of a public point (`Vault+Manager.swift:263-271`). Make an unreadable epoch fail `currentKey()` instead. Lead 3 is one way to reach this.
7. **Share staging, three small things.** `deriveLegacySymmetricKey` reaches `retrievePrivateKey`, which creates the Enclave key on what is documented as a read path (`ShareStagingKeyManager.swift:273-303`, `:168-174`). `manifest.enc` and `inbound/<uuid>.occ` are not excluded from backup (`ShareExtension/ShareViewController.swift:178`, `:392`). The sweep's comment still says a session with no manifest holds plaintext files (`ShareSession.swift:251`).
8. **The attachment base key is derivable by the contact.** It is the identity ECDH under its own label with no device secret (`Key+Manager.swift:361`). Draft attachments for that contact are therefore readable with a device image plus that contact's phone. Bug 196's addendum decided this as low; it did not weigh a seized contact device.
9. **Known items 6 and 13, confirmed variants.** `upgradeIsStranded` also returns "not stranded" when the Keychain read throws (`KeyReseal+Upgrade.swift:173-182`), and a bad draft file after earlier files moved leaves those files under the pending key for the session (`:435-483`). Both are inside the recorded items.
10. **`wrapVerifiers` runs without an epoch.** It runs whenever the reseal returned without throwing, including `.aborted` (`LaunchSequence.swift:164`). Consistent, but the coupling is not documented or tested.
11. **Restore skips entries whose id exists at another depth.** `insertEntries` uses a depth-blind lookup (`Vault+Manager+Backup.swift:294`), so a restore can report success while skipping entries. A recovery-completeness gap.
12. **Stale security comments.** `Vault+Manager.swift:9-10` and `:615-617`; `Key+Manager.swift:927-936` (legacy vault key described without saying it is a function of the public point); `Vault+Manager+Backup.swift:1253-1254` ("the file is the owner's own" although a restore also runs on any delivered file); `forensic-trace-avoidance.md:32` and `:120`.
13. **Five log statements compile into Release.** `OccultaApp.swift:1087`, `Features.swift:16`, `PrekeySecretsManager.swift:278`, `Contact+Manager.swift:388` and `:941`. None carries key material or identifiers; the last prints an error value. Wrap them in `#if DEBUG` for consistency.
14. **CI.** `actions/checkout@v4`, `actions/upload-artifact@v4` and `dorny/test-reporter@v1` are pinned by tag, the last is third-party and runs with `checks: write` and `pull-requests: write`, and `brew install xcbeautify` fetches an unpinned tool (`.github/workflows/ci.yml`). The job holds no secrets. Pin by commit SHA.

**Supply chain, confirmed clean.** The project references one package, the local `OccultaCore` (`Occulta.xcodeproj/project.pbxproj:1072-1077`); `OccultaCore/Package.swift` declares no dependency; there is no `Package.resolved`, Podfile or Cartfile. `TestKeyManager` and the in-memory ML-KEM provider are inside `#if DEBUG` (`KeyManagerProtocol.swift:278-1210`, `PostQuantumProvider.swift:89-101`, `:187-255`).

## Code quality

- **Size and repetition.** `Key+Manager.swift` is 1,921 lines. The five Enclave keys each have their own create and retrieve functions that differ by tag and access flags. One parameterised pair would remove about 250 lines and note 4 with them.
- **Duplicated constants and codecs.** The generator and the nothing-up-my-sleeve point exist in three copies (`Key+Manager.swift:232`, `:255`; `KeyManagerProtocol.swift:384`, `:398`; `ShareStagingKeyManager.swift:81`), pinned by `NUMSPointTests`. The tier PQ record codec exists twice (`TierPQRecord.swift`, `ShareStagingKeyManager.swift:699-774`); the share hunter read them as byte-identical. The duplication is forced by the extension linking one file.
- **The test double is a second implementation.** `TestKeyManager` re-implements every derivation in about 900 lines. A mirror suite compares it with `Manager.Key`'s arithmetic, but the Keychain and Enclave handling around that arithmetic has no double.
- **Force unwraps on security paths.** Nineteen `error!.takeRetainedValue()` and `as! SecKey` sites in `Key+Manager.swift` trap if Security.framework returns nil without an error.
- **Process state.** `Manager.Ambient` holds three static mode variables with no lock. They are safe because the app's default isolation is `MainActor`. Lead 3 shows the cost of state that only launch can set.
- **Naming.** `retrivePublicKey` is misspelled across the key manager and its callers.

## Test coverage and what the gates leave unverified

`OccultaTests` holds about 2,134 Swift Testing tests and 34 XCTest cases. 89 test attributes gate on `secureEnclaveAvailable()` and 47 on a Keychain check. No test uses the old print-and-return skip.

**Well covered by tests that run anywhere:** the reseal and its epochs (`KeyResealTests` 20, `KeyResealEpochGateTests` 6, `KeyResealLaunchTests` 8, `LaunchBlockedTests` 12, `ResealInventoryTests` 10), the hybrid upgrade (`HybridUpgradeTests` 37, `HybridUpgradeVaultTests` 11), the vault rewrap (`VaultRewrapTests` 38), the verifier wrap (`PINVerifierWrapTests` 32) and share sessions through the in-memory key (`ShareSessionTests` 31). These run against `TestKeyManager`.

**Skipped on CI** (unsigned build on a VM, so every Keychain and Enclave gate is false):

- the real `Manager.Key` tier secrets and PQ records (`EnclaveBoundKeyTests`, 7 gated; `EnclaveBoundPostQuantumTests`, 14 gated; `HybridUpgradeRecordTests`, 7 of 8 gated);
- the reseal on the real Enclave (`KeyResealEnclaveTests`, 4 of 4) and `EnclaveGeneratorECDHTests` (12 of 14);
- share staging's Keychain and Enclave paths (`ShareStagingEnclaveBoundTests`, 17 of 19);
- Erase All Data's Keychain half (`KeyResealScaleTests`).

So a green CI run shows the logic against the software double and nothing about the code that talks to the Keychain or the Enclave. That code runs only in a local Simulator run on Apple Silicon.

**Not verified by any automated run, local or CI:**

- the vault key's real access control and `r_B` read through an evaluated `LAContext` (the Simulator cannot unlock the vault; the tests pass a bare `LAContext()` to the double);
- what `.biometryCurrentSet` does to the vault key and `r_B` when enrolment changes;
- ML-KEM blob use across the app and extension processes on a device;
- `KeychainMigrationSETests` (6 cases, device-only). They probe a platform behaviour and exercise no production code: nothing in `Occulta/` implements a keychain migration.

**No test exists for:** the effect of `secure_delete` (no test mentions it), the protection class of the store and its sidecars, using the app after Erase All Data without relaunching, removal of the `blobs` directory, binding of staged files to their manifest, and the full `eraseAllData` path with real key deletion (the tests run it through seams; `EraseAllDataDraftTests`'s header says so).

## Entries for the limitations register

`OPEN_LIMITATIONS.md` exists only in the main checkout, so these are listed here for whoever maintains it. All are "open, needs a decision" unless fixed.

- Deleted rows stay in the store's free pages until reused (lead 1), until a scrub lands and is tested on iOS.
- Devices upgraded from 1.9.2–1.10.3 keep the layer file under a legacy key (lead 2), until a launch cleanup lands. Whether to delete it given the downgrade convention is the owner's call.
- The attachment base key is derivable by the contact, which exposes unsent draft attachments to an examiner who also holds that contact's phone (note 8). Extends Bug 196's addendum.
- The vault tier's ML-KEM key is usable at device unlock without the vault's gate (note 3).
- Key bytes in memory are not zeroed (note 5).
- The Keychain and Enclave code is exercised only by local Simulator runs; the vault's access control by none.

## Filed

Bugs 210–214 in `Docs/Features/Secure Mode/bugs.md`, all `unconfirmed`. The numbers follow the split the three audit sessions agreed in the shared notes (key exchange 198–209, local keys 210–219, secure mode 220–239).

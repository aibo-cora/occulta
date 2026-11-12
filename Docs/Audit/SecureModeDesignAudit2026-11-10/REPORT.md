# Secure Mode design audit — 2026-11-10

Commit `87d9bf11` (`v2.0.1/version-bump`). Method: the `occulta-security-audit` skill, quick profile, on one
subsystem. Run status: **incomplete** (six units deferred; see §7). Nothing in production code was changed.
Nothing was committed. No phone was used.

## 1. Result

Sixteen leads were filed as Bugs 220–235. Seven are reproduced by tests that fail on the iOS Simulator. Two of
those let whoever holds the phone reach the real depth without the master PIN.

| Bug | Proposed severity | Finding | Evidence |
|---|---|---|---|
| 220 | Critical | A duress PIN alone reaches depth 0: add a layer from depth 1, then "Deactivate Protection" lands the session one depth shallower | Test fails (2 variants); found independently by the parent and two hunters |
| 227 | Critical, conditional | The grace period trusts the wall clock: set the device clock back while Occulta is in memory and it reopens at the owner's last depth with no PIN | Test fails (app logic); device half assumed |
| 221 | High | With the lock lowered, setting a PIN moves the session one depth deeper; the decoy's vault entries and drafts vanish | Test fails |
| 222 | High | The app-switcher cover is installed only when Secure Mode is active | Source, verified |
| 228 | High | SwiftData's history log records, with times, every duress unlock that purged drafts, every Secure Mode configuration change and every visibility toggle | Test fails; log is a known item (Bug 196), these signals are not |
| 224 | Medium | Any correct PIN resets the lockout: a duress PIN holder guesses the master PIN five at a time, forever | Test fails |
| 226 | Medium | PIN checks made from Settings are not counted, and `reEnablePIN` tests a guess against every depth's PIN | Test fails |
| 223 | Medium | With the lock lowered, "Learn more" stays enabled and asks for a "Current Passcode" | Source, verified |
| 229 | Medium | `secure_delete = ON` does not persist; the next connection reports FAST | Test fails; SwiftData's own setting not observed |
| 230 | Medium | A real-depth group can be renamed or deleted from a duress depth | Source, verified |
| 225 | Low | `sealedDuressVerifier` is NULL until Secure Mode is activated | Source, verified |
| 231 | Low | Saving a classification rewrites a deeper visibility limit to "visible everywhere" | Source, verified |
| 232 | Low | A contact created at a duress depth shows as Private but stays visible deeper | Source, verified |
| 233 | Low | Adding a layer overwrites an existing deeper layer and inherits its vault and backup key | Source, verified |
| 234 | Low | A freed depth keeps its backup-export record | Source, verified |
| 235 | Low | Erase All Data does not re-seed the config row and leaves `Group` rows | Source, verified |

Severities are the auditor's proposal on the scale in the skill's threat model. The method assigns none.
Details, traces and fix proposals: [FINDINGS-DETAIL.md](FINDINGS-DETAIL.md) for 220–227, and the entries in
`Docs/Features/Secure Mode/bugs.md` for all sixteen. Design-level reading: [DESIGN-REVIEW.md](DESIGN-REVIEW.md).

**What to fix first.** Bugs 220 and 227 before any release: each gives the real depth to someone who was not
given the master PIN. Then 222, 221 and 223, which let a coercer tell Secure Mode is in use by looking. Bugs
224 and 226 want one fix (a single attempt counter), with Bug 62's open Gap 2.

## 2. Scope: what "Secure Mode" was taken to cover

The PIN lock and the stack of duress depths as built on this commit:

- `Manager.Security`, `AppLayerConfig`, `PINManager` (`Occulta/Features/SecureMode/`);
- the lock, grace period and session reset (`Occulta/App/`), `PINEntry`, the Settings → Security screen, the
  setup and deactivation flows, contact classification;
- the depth filter wherever it applies: contacts, groups, drafts, vault entries, backup keys, shard custody,
  identity challenges, cards, the share extension, inbound files;
- what the store, files, keychain and app switcher show about depths.

The written design read against it: `plan.md`, `scenarios.md`, `forensic-trace-avoidance.md`,
`SECURE_MODE_DECRYPT_CONTRACT.md`, `USER_GUIDE.md`, `Docs/v2.0.0/*`, the per-issue docs in `Docs/Bugs/`.

**On this commit Secure Mode is UI-layer filtering.** Every depth's rows are in one store under one
device-released key. The blob and key rotation were removed on 2026-09-10. The passphrase layer keys
(`PASSPHRASE_LAYER_KEYS.md`, `PASSPHRASE_ROLLOUT.md`) are proposed and not built; they were read to see which
findings they change, not audited.

Out of scope here, covered by the sibling audits of the same date: the key exchange ceremony and the local
encryption keys.

## 3. Method and deviations

1. Recon: two read-only agents (a surface map of every screen, artefact and depth call site; an inventory of
   43 known limitations so they are not re-reported). The auditor read `Manager+Security.swift`,
   `AppLayerConfig+Model.swift`, `PIN+Manager.swift`, `PINEntry.swift`, the Settings screen and the setup flow
   in full and wrote the architecture note.
2. Coverage ledger: 10 units, each a surface × a boundary × an attack class.
3. Hunting: six isolated hunters over the 10 units.
4. Verification: every lead went to a verifier that had not hunted it and was told to refute it from source.
   17 records: 15 stand, 2 rejected.
5. Final coverage critic: named six units nobody covered.
6. Proof: the auditor wrote tests for seven leads and ran them on the Simulator.

Deviations from the skill, all recorded in `run-metadata.json`:

- A subsystem, not a branch diff.
- Recon was two agents, not five.
- The first six hunters (Fable) were stopped by usage limits before reading any source and were relaunched on
  Sonnet. The skill notes Sonnet hunters are untested. Here eight of the sixteen leads came from them alone
  (226, 227, 229, 230, 232, 233, 234, 235), three from them and the auditor independently (220, 224, 231),
  four from the auditor alone (221, 222, 223, 225), and 228 from a hunter's question that the auditor checked
  against a store file.
- Six leads began with the auditor, before hunters were assigned. They were packaged and verified like any
  other. A verifier corrected line numbers in several records; the corrected lines are the ones cited.
- The method reads source only and treats every lead as `needs_validation`. The Simulator tests go beyond it,
  under the task's permission for Simulator runs.
- Structural fix by the auditor to no record. Both validators pass on `findings.json` (17) and
  `coverage-ledger.json` (16).

Agents: 2 recon, 6 hunters, 5 verifiers, 1 critic, all Sonnet; 6 Fable hunters abandoned.

## 4. Rejected leads

Kept so a later run does not repeat them without new evidence.

| Lead | Why rejected |
|---|---|
| `secure-mode:deactivate-at-coercer-base-depth-pops-to-depth0` | Duplicate of Bug 220's record, found by a second hunter. The claim is right. |
| `swiftdata-store-bookkeeping-outside-sealed-columns` | Its claim that no document mentions SwiftData's history tables is wrong: Bug 196 records them as open under Bug 190, and the 2.1.0 store was decided on 2026-11-01 to remove them. The auditor's first draft of Bug 228 repeated the wrong claim and was rewritten. What survives as Bug 228 is narrower: the Secure Mode writes that entry does not consider, which do depend on the depth. |

## 5. Known items confirmed still present (not re-filed)

- **Bug 119**: every depth opens with the device passcode. The design documents say so; the user guide does not
  (register §E).
- **Bug 62 Gap 2**: no limit on collision probes in the activation flow. Bugs 224 and 226 are two more paths
  to the same search; fix together.
- **Bug 173** (approving a hidden contact's identity challenge): still open; the key exchange audit notes its
  guard test is absent on this branch.
- **Bugs 103/104** (a hidden sender's message renders its sender): accepted; unchanged.
- **Erase All Data reachable at a duress depth** behind a confirmation only: partly fixed, panic-wipe entry
  undecided.
- **Bug 206** (key exchange audit): unknown-sender rejection time depends on cards issued at hidden depths.

## 6. Hardening notes

No boundary violation was established for these. They are the hunters' notes with their line references; the auditor read the ones about `Manager.Security` and `AppScreen` and did not re-check the rest.

- **A custody manifest from a hidden trustee is still applied at a duress depth** while that sender's shard
  operations are dropped (`OccultaApp.swift:1033-1046`, `ShardCustody+Manager.swift:291-338`). The dropped
  operations are consumed with the message and not retried, so the owner can lose a recovery piece.
  `filterShardOperations`' comment and `RECOVERY_BUFFER_LAYERING.md` §2.1 describe the gate as covering both.
- **A bundle queued while locked and drained by a duress PIN** is opened there and its prekey spent; the owner
  never sees that message. Decided behaviour; the user guide should say so.
- **The cover is removed before `PINEntry` is known to be on screen** (`AppScreen.swift:104-111`): one frame of
  the unlocked tree may show on a warm return past the grace period. Needs a device.
- **`requiresPIN` fails open**: a failed fetch of the config row reads as "no PIN" and unlocks
  (`Manager+Security.swift:78-81`).
- **`approvePending`** sets its result after a biometric prompt with no session check
  (`IdentityChallenge+Coordinator.swift:262-312`).
- **The pasteboard is not cleared at `endSession`**: text copied at one depth is pasteable at another for up to
  120 s. Extends the accepted O2.
- **`pendingFileData` is one slot**: a second file arriving while locked replaces the first, whose source copy
  is already deleted.
- **`ContactManager.save(contact:)` defaults `currentDepth` to 0**. Only unreachable v1 screens rely on it. Make
  the parameter required or delete the screens.
- **The 32-depth ceiling**: writes at index 32 are dropped silently while callers report success
  (`AppLayerConfig+Model.swift`), so a PIN set at depth 31 cannot route.
- **Twenty wrong PINs lock the owner out for 24 hours**, and each reboot starts the delay again
  (`Manager+Security.swift:656-663`). Anyone holding the phone can do it. The lockout also runs on a clock that
  stops while the phone sleeps, so it lasts longer than it says.
- **Orphaning returns silently if the key is unavailable** after verifiers are already cleared
  (`Manager+Security.swift:557`, `:616`); and `VaultEntry.isOrphaned` treats an unreadable token as orphaned,
  which the 50-row eviction can then delete.
- **`restoreBackup` returns early when the depth already has a key**, skipping work a keyless depth does: a
  timing difference between depths with the same message.
- **Draft purge runs only in `applyVerifyState`**; `reEnablePIN` and the lowered-lock restore in `init` change
  depth without it.
- **Checkpoints ignore their result** and set no busy timeout; a deeper unlock checkpoints twice, a real one
  once.
- **The vault Enclave key is created at first vault unlock**, so its keychain date marks first vault use.
- **`debugPrint`/`print` outside `#if DEBUG`** (`OccultaApp.swift:1087`, `:1147`, `Contact+Manager.swift:388`,
  `PrekeySecretsManager.swift:158`, `:278`). Stdout only.
- **Dead code**: `forceDeactivateForRecovery`, `checkNormalPIN`, the v1 Contacts screens.
- **Stale documents**: see DESIGN-REVIEW.md. `scenarios.md` §6.4 ("Only depth 0 can deactivate") is wrong and
  would steer a reviewer away from Bug 220.

Patterns the hunters checked and found holding:

- Nothing is processed or shown before the PIN on a file open, `occulta://` or share handoff; the share picker
  offers only contacts visible at the current depth.
- The inbound decrypt and sender-resolve path does the same work at every depth.
- Card import at depth N stamps the new contact with N and attaches only to contacts visible at N.
- Read mode in the message viewer has no reply or compose.
- Pre-PIN launch work takes no depth input, and its failure screen is the same at every depth.
- The verifier arrays and `pinEnabledPerDepth` are fixed-size with filler of matching length.

## 7. Coverage

16 units: 6 produced leads, 4 covered with none, 6 deferred. The critic ran. No unit is claimed clean beyond
what its recorded checks say.

Deferred (named by the critic, not hunted):

1. Erase All Data at a duress depth and what it leaves.
2. The key exchange transport at a duress depth, including what happens when an exchanged identity matches a
   contact hidden at the current depth. The key exchange audit covers the ceremony; this depth question is not
   known to be covered by either.
3. Contact lifecycle at a duress depth: `deleteContact` has no visibility check, the 50-row soft-delete
   eviction, `discardCardConversation`.
4. Compose and send at a duress depth: prekey use, sweeps limited to visible contacts.
5. A `.occbak` staged before the PIN and carried across a depth change.
6. Received attachments, Quick Look and temp files.

Also not done: no finding was observed on a device; the on-screen paths of Bugs 220–223 were read, not driven;
no store file was inspected beyond its schema and row counts; recall is unmeasured.

## 8. Limitation entries for `OPEN_LIMITATIONS.md`

The register is gitignored and lives in the main checkout, so it was not edited. Entries to add there, each
**open, needs a decision** unless it says otherwise:

- Bug 221: what a PIN set on a lowered lock should open (the fix costs the owner's old duress PIN for that
  depth).
- Bug 226 / lowered lock: there is no way to lock a lowered-lock session, so the owner's route back to depth 0
  is `reEnablePIN`'s scan of every depth; closing the scan needs a replacement. What the lowered lock is for.
- Bug 228: whether 2.0.1 gets a history purge before the 2.1.0 store; `Z_PRIMARYKEY.Z_MAX` counts every row
  ever created and no purge removes it.
- Bug 229: free pages may hold old ciphertext under FAST; what SwiftData's connections actually use is
  unmeasured.
- Bug 230: rename and delete of a shared group from a duress depth; the per-depth "hidden here" mark it needs.
- Bug 232: whether a contact created at a duress depth is meant to be un-hideable from deeper depths.
- Bug 227 residual: the end-to-end clock test on a phone with no real data.
- Bug 222 residual: installs without Secure Mode write their contacts list into the app-switcher snapshot.
- Register §E: the user guide's "even law enforcement cannot decrypt" and "No button to disable it" lines,
  against Bug 119 and Bug 220.
- The six deferred units of §7.

## 9. Tests added, and what running the suite now shows

Two untracked files in `OccultaTests/SecureMode/`, eight tests, **all written to fail while the bugs are
present, and all failing**:

- `DuressDeactivationEscalationTests.swift` (6): Bugs 220 (two), 221, 224, 226, 227.
- `StoreForensicTraceTests.swift` (2): Bugs 228, 229.

A full local run therefore shows eight failures until the fixes land or the files are moved out of the target.
They run anywhere: they use `TestKeyManager` under `.ambientTestKeyManager` and need no Enclave. The
existing tests that assert Bug 220's behaviour as intended (`PINManagerTests.swift`:
`deactivation_fromDepth2_popsOneLevelToDepth1`, `deactivation_fromDepth3_popsOneLevelToDepth2`,
`deactivation_threeLayerStack_popsOneLevelPerCall`) must change with the fix.

## 10. Files

| File | Contents |
|---|---|
| `REPORT.md` | This file |
| `FINDINGS-DETAIL.md` | Bugs 220–227 in full |
| `DESIGN-REVIEW.md` | The design against its threat model, spec-to-code gaps, recommendations |
| `NEEDS-VALIDATION.md` | What each lead still needs before it is confirmed |
| `findings.json`, `coverage-ledger.json`, `run-metadata.json` | The validated records |
| `known-limitations.md`, `surface-map.md` | Recon output the hunters worked from |

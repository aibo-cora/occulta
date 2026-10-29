# Security audit report — Occulta, scoped quick run

## 1. Run profile and scope

- **Profile:** `quick`, scoped to the three-dot diff `develop...v2.0.0/introduction-cards`: merge base `3319fd7` to `8c51ad97`, 105 production, build and CI files. Tests and docs were read for intent only. **This is a partial pass.**
- **Source ref:** `8c51ad97`, clean. The branch has since moved to `b471bac`; this report covers `8c51ad97` only.
- **Execution:** sandboxed source-and-local-only. **No target code ran.** No OS-enforced sandbox can contain an Xcode/Simulator test run on this host (recon-1d), so every check is source-only. No record can reach `confirmed`.
- **Prior runs:** none.
- **Budget:** none was set. The run owner trimmed the run after three usage-limit stops.
- **Agents:**
  - 5 reconnaissance agents (Opus).
  - 13 hunters (Opus): 9 returned results and 4 were stopped and not resumed.
  - 0 coverage critics.
  - 6 verifiers (Sonnet), each checking a batch of 2–4 candidates.
- **Deviations from the skill, all chosen by the run owner or forced by the platform:**
  - Occulta's threat model was added to Phase 1, overriding the skill's same-principal rule for a coercer at a duress depth.
  - A fifth reconnaissance agent built a known-limitations inventory.
  - Hunters wrote their structured results to their own `scratch/`.
  - Phase 3 and Phase 5 were merged, as the quick profile allows, and run by Sonnet verifiers on batches of 2–4 candidates instead of one fresh Opus verifier per candidate.
  - **The mandatory final coverage critic did not run, so this report makes no clean-coverage claim.**
  - Four hunter assignments, covering 6 units, were deferred unrun.
- **Deferred and out-of-scope coverage:**
  - Deferred by the run owner's trim: in-person exchange and card meeting check, CI workflow, shard/custody and `.occbak` restore, store migrations, obvious exposures, wildcard.
  - Deferred because a quick run has one hunting wave: 5 surfaces hunters reported as uncovered. These are the local DB/vault/custody key derivations, revocation then re-exchange, group draft attachments, `inbound/` handoff files, and sender-resolution timing.
  - Everything outside the diff is out of scope.

## 2. Security posture

No confirmed vulnerabilities. That follows from the run executing nothing, not from a clean result. 18 leads survived independent source review, and 2 candidates were refuted.

The leads cluster in three places:
- **Duress-depth isolation.** A coercer can act on, or observe, hidden-depth state through identity challenges, drafts, the contacts list, group counts, error text and re-opened files.
- **Crafted-file traps.** Contact-supplied lengths and dates reach trapping Swift conversions before authentication.
- **Card and prekey lifecycle edges.**

One lead questions a construction the whole key hierarchy uses: an "Enclave component" derived as `ECDH(d, G)`, which equals a function of the public key.

## 3. Confirmed findings

None.

## 5. Needs validation (no severity)

Each lead's trace, blockers and local plan are in NEEDS-VALIDATION.md.

| # | Lead | Boundary (entry → sink) |
|---|---|---|
| 1 | Negative custodyManifestCount in a group slot traps openGroup | `OccultaApp.swift:1074` → `Contact+Manager.swift:2107` |
| 2 | At a duress depth, approving a hidden contact's identity challenge signs a valid response and seals it to that contact | `OccultaApp.swift:1081` → `IdentityChallenge+Coordinator.swift:297` |
| 3 | Outstanding identity challenges and verified-at state survive endSession into a duress session | `IdentityChallenge+Coordinator.swift:103` → `IdentityChallenge+Coordinator.swift:250` |
| 4 | Out-of-range SignedAttribute dates in inbound shard operations trap signature verification | `OccultaApp.swift:1091` → `SignedAttribute.swift:152` |
| 5 | Crafted .occ length field traps WireHandle and terminates Occulta before authentication | `OccultaApp.swift:687` → `WireHandle.swift:414` |
| 6 | Share staging key is a function of the Enclave key's public point, not of its private key | `ShareViewController.swift:200` → `ShareStagingKeyManager.swift:159` |
| 7 | Attachments for card contacts and groups are staged and kept as drafts in plaintext, though the design says they are sealed under the per-contact file key | `ContactDetailV2.swift:95` → `DraftStore.swift:213` |
| 8 | Erase All Data leaves every Message.Draft row and the Application Support/Drafts/ attachment files | `Settings.swift:176` → `Message+Draft.swift:161` |
| 9 | A copy of a group bundle with an altered outer header uses up the recipient's one-time prekey, and the genuine message can then never be opened | `OccultaApp.swift:1040` → `Crypto+Manager+GroupDecrypt.swift:217` |
| 10 | With two contacts holding the same peer card key, a slot sealed to a last-resort key or a long-term card slot goes to whichever contact sorts first and is rejected | `OccultaApp.swift:1052` → `Crypto+Manager+Cards.swift:302` |
| 11 | A coercer at a duress depth can re-open archived re-openable .occ files from a hidden contact and read them on demand | `OccultaApp.swift:687` → `OccultaApp.swift:884` |
| 12 | Inbound error text tells a coercer whether a file's sender is a contact hidden at the current depth | `OccultaApp.swift:687` → `OccultaApp.swift:955` |
| 13 | Card conversation on a revoked contact seals replies to the revoked device's prekeys | `TrustCheckV2.swift:182` → `Crypto+Manager+Cards.swift:73` |
| 14 | Shard state from before a contact became a card contact makes every card send throw hardBlocked | `ComposeViewModel.swift:282` → `ContactManager+Cards.swift:406` |
| 15 | Contacts list empty state and trust summary are keyed on the unfiltered contact query, revealing hidden contacts at a depth with none visible | `ContactsListV2.swift:53` → `ContactsListV2.swift:151` |
| 16 | A group draft written at the real depth loads into the group's compose field at a duress depth | `ContactsListV2.swift:255` → `ComposeHeroV3.swift:60` |
| 17 | Group capacity and share-picker eligibility count members hidden at the current depth | `Group+FormV3.swift:154` → `ContactListFilter.swift:53` |
| 18 | After a contact's clock goes back, a replayed bundle on a reopenable slot can bring back their newest-dated batch, whose keys they have already deleted | `OccultaApp.swift:1074` → `Contact+Manager.swift:1315` |

Rejected candidates are kept so future runs don't repeat them without new evidence:

| Rejected candidate | Why |
|---|---|
| Sender-supplied File.url survives basket rebuild for non-file entries and is deleted on read-sheet dismiss | Source confirms the chain: File.url is synthesized Codable (Basket.swift:36), the .v3fs and legacy paths feed JSONDecoder (OccultaApp.swift:1160, 1167), the default branch appends non-.file entries unchanged (:1203-1204), and onDisappear removes every file.url (:529-532). It stops at the destination… |
| Card redemption accepts an introduction agreement key the sender does not hold, including the issuer's own card key, which enables reflection of the issuer's own messages as the peer's | The mechanics hold in source, but no boundary is crossed and nothing is gained. (1) The only party that can name Bob's own card key is the card redeemer, and a redeemer can already author any content that Bob attributes to the card contact (first-to-use-wins, FINDINGS.md:303; card contacts carry the… |


## 6. Hardening notes and positive patterns

**Hardening notes** (no reachable boundary violation established in this run). Selected:
- `purgeDraftsNotSafeAtCurrentDepth` runs only for `.duress`. An activated duress PIN routes as `.normal(depth: 1)`, so the purge may never run (`Manager+Security.swift:751-753`; `PINManagerTests.swift:206-219`). **Worth checking first: this could be a dead duress control.**
- `openGroup` throws `missingGroupID` after `save(prekeys)` has persisted the accepted batch (`Contact+Manager.swift:2074-2081`).
- `cancelCard` writes `.empty` without re-checking `.issued`. A redemption between the dialog and the confirmation loses the live conversation's keys (`ContactManager+Cards.swift:155-158`).
- A redeemer can name the generator as the introduction agreement key, which makes the classical half of long-term card slots public. The ML-KEM half still protects the content.
- Card signatures are raw r‖s with no low-S rule. Exact-byte card comparison (`CardRules.swift:96-97`) may treat a malleated card as a different card.
- Duplicate identity keys across a hidden and a visible contact let `identifyOwner` pick by sort order (`Contact+Manager.swift:1616-1625`).
- Unguarded `debugPrint` in Release (`PrekeySecretsManager.swift:278`, `Contact+Manager.swift:372`, `:812`). This is stdout only.
- The scheme comparison in `handleOpenURL` is case-sensitive (`OccultaApp.swift:691`). `occulta://share` with a random UUID still presents the recipient picker.
- `inbound/` handoff files are never swept, and Erase All Data skips the share staging key. Both were fixed after the audited commit (`9e7e9157`, `74b99161`).

**Positive patterns** the hunters checked and found holding:
- The card field is a fixed 12 KiB sealed value in every state.
- Card, ML-KEM and prekey Enclave keys create no keychain items.
- The first-message view is the same at every depth.
- `ContactsV2.open` refuses requests for hidden contacts.
- The body digest is checked before prekey consumption on the body path.
- Group send filters stale hidden members.

## 7. Coverage summary (from coverage-ledger.json)

- 28 units: 15 candidate, 2 covered, 11 deferred, 0 blocked.
- 20 candidate records: 18 `needs_validation`, 2 `rejected`.
- The final critic did not run. Coverage is partial, and no part of it is claimed clean.
- Both skill validators pass: `validate-findings.cjs` (20 findings) and `validate-coverage-ledger.cjs` (28 units).

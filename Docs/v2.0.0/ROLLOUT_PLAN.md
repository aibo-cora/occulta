# v2.0.0 — Rollout Plan

**Status:** Proposed, 2026-09-30. Not decided. Step numbers refer to
[HARDENING_STEPS.md](HARDENING_STEPS.md). If this plan is adopted, it replaces the single-migration
assumption in [`PASSPHRASE_LAYER_KEYS.md`](../../Occulta/Features/SecureMode/PASSPHRASE_LAYER_KEYS.md)
§5.

**Summary.** Steps 6–16 and 17a don't depend on each other and can ship one at a time, in any order.
Steps 1–5 can be split by data (vault first, then contacts), but not step by step. 17b ships with the
contacts slice. The rules below stay fixed
however the stages are cut.

## Rules that can't be staged

1. **Split steps 1–5 by data, not by step.** Steps 1 and 2 are one key derivation. Adding 2 later
   changes the key and forces a second full reseal. Shipping 1 without 3 is still better than today,
   but it also costs a second full reseal. That is the riskiest operation in the app, and this
   codebase's data-loss bugs have clustered there (Bugs 75–78, 138). Each slice of data gets all five
   steps at once.
2. **All depths on a device switch together.** If each depth switched on its next unlock, the everyday
   depth would switch first and the duress depths would stay on PIN verifiers for weeks. That
   difference points straight at the real depth. The user sets up every depth's phrase in one sitting.
3. **The phrase replaces the PIN for everyone who uses an app lock.** Today the PIN is an optional
   lock that any user can turn on (`AppScreen`: `.covered → .unlocked` when there is no PIN). If only
   users with duress depths got a phrase screen, the screen itself would announce hidden depths. An
   opt-in period is acceptable only if every lock user is offered it. Keep it short, because whoever
   opts in early marks themselves as security-conscious.
4. **Keep the old keys until the user proves they remember.** Keep the old device keys until every
   phrase has been entered correctly a few times over about a week. Then delete the old keys for all
   depths at once. Until the deletion nothing is safer, but a forgotten phrase can't cause data loss.
   The deletion is also what makes any leftover old ciphertext on disk unreadable.

## Release mechanics

- **There is no remote kill switch.** `features.plist` is compiled into the build and the app has no
  network. Every stage must be safe for everyone who installs it.
- **TestFlight first**, on real devices with several depths configured. The Simulator can't unlock the
  vault.
- **App Store phased release** spreads a migration release over 7 days for automatic-update users. It
  only limits damage if users report problems, because the app sends no telemetry.
- **Migrations are one-way.** An older build can't read resealed data.

## Stages

| Stage | Ships | What someone holding the phone and passcode gets afterwards |
|---|---|---|
| **0 — nothing users see** | 9 CI trace check, 12 fuzzing, 13 drop keys on background, 10 advertising only in foreground, 14 signing checks, 15 account hardening | Same as today. This stage closes supply-chain risk and stops known leak types from coming back. |
| **1 — additions old versions tolerate** | 6 prekeys in the exchange, 7a post-quantum status shown, 8 mandatory comparison, 11 wording pass, 17a per-contact secret for classical-only pairs and keyed sender fingerprint | Same on the phone. Messages between two updated contacts are forward-secret from the first one, and the exchange can't be intercepted. |
| **2 — vault slice** | Steps 1–5 applied to vault entries; the phrase replaces the PIN | Vault content stays sealed without the phrase, and the PIN verifiers are gone. Contacts' depth stamps are still readable, so the number of depths still leaks. |
| **3 — contacts slice** | Steps 1–5 applied to contacts, 17b random prekey tags and random padding, then the old local-DB key is deleted | Only what the surrendered phrase opens, apart from the items step 17 lists as open. |
| **4 — the rest** | Steps 1–5 for backup-key, custody-shard and restore records; 7b refuse classical-only sends; 16 in-app guidance | The remaining records close. |

### Stage 0

Each step is its own PR. Step 14 is a gate before any App Store submission, not a feature.

**Done when:** the CI check (9) fails on a planted violation of each kind it covers, the fuzz targets
(12) run in CI, and the signing results (14) are recorded in `SECURITY_CHECKLIST.md`.

### Stage 1

- **6** is a wire-format addition. A new client sends prekeys, an old client ignores them, and anything
  from an old client still arrives as fallback. The payload's size must not depend on Secure Mode state.
- **7a** only displays status. **7b**, refusing classical-only sends, waits for Stage 4. It needs enough
  of the contact population on iOS 26 or it just blocks messaging.
- **8** is a UX change: no contact saves without the comparison.
- **11** goes through counsel in one pass, as register §E asks. Step 16's copy depends on it.
- **17a** is a protocol addition negotiated through `maxBundleVersion`: a pair uses it only when both
  sides support it. The per-contact secret protects nothing until Stage 3 seals the contact records. It
  ships here anyway so the population upgrades early, which shrinks the "senders on old versions" open
  item by the time Stage 3 lands. The keyed sender fingerprint helps from the day a pair upgrades. It
  doesn't depend on Stage 3.

**Done when:** the exchange is tested old→new, new→old and new↔new; a first message after an exchange
is shown to use a prekey; saving without a comparison is shown to be impossible; and a classical-only
pair is shown to open in the new mode only with the per-contact secret, both for a pair set up at the
exchange and for one upgraded in band; and an upgraded file is shown not to match
`SHA-256(senderPublicKey ‖ nonce)` for any nonce it carries, in single, group and identity-challenge
bundles.

### Stage 2 — vault

**Blocked on the spec's §2**: how one row opens under every depth's key. It is unresolved. Design it
for vault and contacts together, even though the vault ships first. Otherwise contacts, where one
contact can be visible at several depths, may force the vault to be migrated a second time.

**Why the vault first:** it holds the most sensitive content (seed phrases, keys, passwords), and it
already has fixed-count rows (`deletionToken` orphan-in-place, Bugs 110–114).

**Known gap until Stage 3:** contacts stay under the device key, so their depth stamps still reveal how
many depths exist.

### Stage 3 — contacts

The hardest slice (see Stage 2). It ends with deleting the old local-DB Secure Enclave key, which is
what turns every leftover old-key ciphertext into noise.

**17b** ships in this slice because the prekey-tag map lives in the contact record. Every dummy key must
exist before any old `prekey.<contactID>.*` tag is retagged. Whether an Enclave key's tag can be updated in place has to be
checked on a device first, because the Simulator is unreliable for that kind of update.

### Stage 4 — the rest

The remaining depth-stamped records: `BackupEncryptionKey`, custody shards, and pending and completed
restore records. Then 7b and 16.

## Required before Stages 2 and 3 count as done

Each needs tests and a no-data-loss migration plan before it counts as done. The plan must cover:

- **An end-to-end "data survives" test for the reseal.** None exists today (register C3, "TEST-2"). It
  needs the `Manager.Crypto()`/`Manager.Key()` injection seam that C3 describes, which also makes the
  test runnable off-Enclave.
- **Never destroy the only copy before the replacement is saved and verified** (Bug 138). Every row
  must decrypt under the new keys before anything old is deleted.
- **Interruption at any point is recoverable and leaves nothing behind** (Bug 139: an interrupted
  rotation left keys that nothing deleted).
- **Rule 2 and Rule 4 enforced in code, not in the UI flow.** Every depth migrates in one step, and the
  old keys are deleted for all depths in one step.
- **Prekeys survive the retagging** (Stage 3). A message sent to a prekey before the migration still
  opens after it, and no `prekey.<contactID>.*` tag remains.
- **The in-progress state leaks nothing about depths.** Being mid-migration may be visible. Which depth
  is ahead of which must not be.
- **Schema change through a migration plan.** The project has no `VersionedSchema`/`SchemaMigrationPlan`
  (register §G), and a change of this size shouldn't rely on SwiftData's inference.

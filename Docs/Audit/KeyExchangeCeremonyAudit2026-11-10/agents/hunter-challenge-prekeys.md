# h-challenge — identity challenge, prekeys and forward secrecy (commit 87d9bf11)

Read-only review. Nothing was built or run, so every candidate below is a code trace, not a reproduced failure.
Paths are relative to the repo root unless absolute.

## 1. Coverage

### Read fully

| File | Lines |
|---|---|
| `Occulta/Features/IdentityChallenge/IdentityChallenge+Coordinator.swift` | 1–363 |
| `Occulta/Features/IdentityChallenge/IdentityChallenge+Manager.swift` | 1–621 |
| `Occulta/Features/IdentityChallenge/IdentityChallenge+Crypto.swift` | 1–146 |
| `Occulta/Features/IdentityChallenge/IdentityChallenge+Payload.swift` | 1–164 |
| `Occulta/Features/IdentityChallenge/IdentityChallenge+Ledger.swift` | 1–90 |
| `Occulta/Features/IdentityChallenge/IdentityChallenge+Store.swift` | 1–95 |
| `Occulta/Features/IdentityChallenge/IdentityChallenge+Constants.swift` | 1–45 |
| `Occulta/Features/IdentityChallenge/IdentityChallenge+View.swift` | 1–332 |
| `Occulta/Features/IdentityChallenge/ChallengeState.swift` | 1–167 |
| `Occulta/Features/IdentityChallenge/ContactManager+ChallengeLedger.swift` | 1–182 |
| `OccultaCore/Sources/OccultaFormats/IdentityChallengeEnvelope.swift` | 1–80 |
| `Occulta/Features/Forward+Secrecy/Prekey.swift` | 1–70 |
| `Occulta/Features/Forward+Secrecy/PrekeyBookkeeper.swift` | 1–387 |
| `Occulta/Features/Forward+Secrecy/PrekeyRecord.swift` | 1–115 |
| `Occulta/Features/Forward+Secrecy/PrekeyRecordCodec.swift` | 1–119 |
| `Occulta/Features/Forward+Secrecy/PrekeySecretsManager.swift` | 1–358 |
| `Occulta/Features/Forward+Secrecy/Crypto+Manager+KeyDerivation.swift` | 1–174 |
| `Occulta/Features/Forward+Secrecy/Crypto+Manager+ForwardSecrecy.swift` | 1–148 |
| `Occulta/Features/Forward+Secrecy/Crypto+Manager+GroupDecrypt.swift` | 1–332 (for prekey consumption) |
| `Occulta/Features/Forward+Secrecy/ForwardSecrecy.swift`, `Contact+Model+Profile.swift` | all |
| `Occulta/Services/Contact+Manager+Prekeys.swift` | 1–261 |
| `Occulta/Features/Pairing/PairingOffer.swift` | 1–231 (first-batch acceptance) |

### Read partially

| File | Lines | Why |
|---|---|---|
| `Occulta/Services/Contact+Manager.swift` | 480–770, 1222–1680, 1721–1760, 1840–2069, 2140–2460 | `deleteContact`, `update(key:)`, `reset(identity:)`, `encryptBundle`, `sendGroupBundle`, `identifyOwner`, `decryptSealed`, `openGroup`, `Authenticated` |
| `Occulta/Services/Contact+Manager+Pairing.swift` | 1–123 | `installPairingPrekeys` |
| `Occulta/Services/Exchange+Manager.swift` | 80–200, 380–450 | where the first batch is made and accepted |
| `Occulta/Services/Key+Manager.swift` | 350–500, 1720–1830 | session-key derivations |
| `Occulta/Features/Forward+Secrecy/Crypto+Manager+GroupEncrypt.swift` | 290–390 | `wrapRecipient` |
| `Occulta/App/OccultaApp.swift` | 278–380, 495–590, 930–1220 | inbound routing, sheets, `endSession`, unlock sweeps |
| `OccultaCore/Sources/OccultaFormats/OccultaBundle.swift` | 340–670 | `SealedPayload`, `PrekeySyncBatch`, `lastResortPrekeyID` |
| `OccultaCore/Sources/OccultaFormats/WireHandle.swift` | 200–330, 440–560 | payload decode, `Reader` |
| `OccultaCore/Sources/OccultaFormats/PairwiseDerivation.swift` | 59–111 | `batchDigest`, `transcript` |
| `Docs/Features/Prekey Continuity/DESIGN.md` | 1–460, 539–678 | intent |
| `Docs/Features/Secure Mode/bugs.md` | Bugs 104, 155, 166, 173, 195, 196 (head) | known items |
| `OccultaTests/Forward+Secrecy/PrekeyBookkeeperTests.swift` | 1–170 | what `accept` is tested against |

## 2. Candidates

### HC-1 — A contact's prekey batch is accepted without checking the keys are curve points, so one bad batch stops every send to them, and to any group they are in

**Proposed severity:** medium (a contact causes lasting denial; in a group, denial of the owner's messages to every other member).

**Evidence**

- `PrekeyBookkeeper.swift:158-161` — `fitsLimits` checks only `publicKey.count == 65` and the ID length.
- `PrekeyBookkeeper.swift:128-130` — the last-resort key gets the same check plus "ID is a UUID".
- `Contact+Manager+Prekeys.swift:123-135` — `acceptInboundBatch` adds nothing.
- `OccultaTests/Forward+Secrecy/PrekeyBookkeeperTests.swift:31-33` — the tests' own `wire()` builds keys from `randomBytes(65)`, which are not points, and `accept` takes them.
- By contrast `PairingOffer.swift:183-186` (`isP256Point`) validates the pair keys in the same exchange message, but not the batch beside them (`Contact+Manager+Pairing.swift:112-116`).
- Send side: `Contact+Manager.swift:1305-1311` takes the key; `Crypto+Manager+GroupEncrypt.swift:329` → `Crypto+Manager+KeyDerivation.swift:32-40` checks length, then `deriveSessionKey` → `Key+Manager.swift:419-441` or `1728-1756`, where `convert(material:)` / `SecKeyCopyKeyExchangeResult` return nil for a non-point, so `deriveOutboundKey` throws `keyDerivationFailed`. Nothing catches it and falls back.

**Attack trace**

1. Attacker: contact M, or whoever holds M's phone. M sends one ordinary message whose slot carries a `PrekeySyncBatch` with a fresh 16-byte `id`, 15 keys of 65 bytes that are not points (for example first byte `0x00`), and a `lastResort` with a UUID `id` and the same kind of key.
2. `openGroup` (`Contact+Manager.swift:2389`) or `decryptSealed` (`:1988`) calls `acceptInboundBatch`; `accept` passes and stores them. `inboundLastResort` is replaced (`PrekeyBookkeeper.swift:152`).
3. Once any earlier valid keys are used up, every `encryptBundle` to M takes a bad key and throws. Each failed attempt removes one key (see HC-2), and after the 15 are gone the last-resort key is chosen (`Contact+Manager.swift:1308-1311`). It is never removed, so every later send throws.
4. Nothing recovers: the long-term mode is only used when there is no one-time key and no last-resort key. Only a new, valid batch from M replaces it. The compose indicator (`nextSendSecrecy`, `Contact+Manager+Prekeys.swift:66-75`) keeps saying "Forward Secret" / "Temporary Key".
5. Group case: `sendGroupBundle` (`Contact+Manager.swift:1543-1626`) seals every member in one `seal`, so M's bad key makes the whole group send throw. The owner can't message the group at all while M is a member, and each attempt also removes one one-time key from every other member (HC-2).

**Why existing guards don't stop it:** the batch is authenticated (only M can send it), but nothing validates its content beyond sizes. The "no silent degradation" rule (`Crypto+Manager+ForwardSecrecy.swift:33-39`) turns a bad key into a hard failure.

**Confidence:** medium-high. That `accept` stores non-points is certain. That the send throws rests on Security.framework refusing a non-point, which I did not run; a key whose first byte isn't `0x04` is the safest test input.

**Fix**

- In `PrekeyBookkeeper.accept`, require each key, and the last-resort key, to load as `P256.KeyAgreement.PublicKey(x963Representation:)`, and throw `malformedBatch` otherwise. `fitsLimits` is also used by the launch migration, so decide whether carried-over keys get the same rule.
- Defence in depth on the send side: when the derivation to a prekey fails, drop that key and try the next, ending in the long-term mode, so a record already holding bad keys recovers.
- Validate the exchange's peer batch the same way in `PairingOffer.accepted`.

**Test plan**

- Pure, runs on CI: in `PrekeyBookkeeperAcceptTests`, `accept` a batch whose key is 65 bytes starting `0x00`, and one with such a last-resort key; expect `malformedBatch` and an unchanged record. Fails today. The suite's `wire()` helper then has to produce real points.
- `.ambientTestKeyManager`, Simulator: a contact whose record holds such a batch; `encryptBundle` must produce a bundle. Today it throws.
- Same for a two-member group where one member's record holds the bad batch: `encryptGroupBundle` must succeed, or at least leave the other member's `inboundBatches` count unchanged.

### HC-2 — A send that fails after taking the contact's one-time key still uses the key up; the group path's "autosave off" comment claims otherwise

**Proposed severity:** low (no secret is exposed; the owner's forward-secret stock for a contact drains without a message being sent, ending on the reusable last-resort key).

**Evidence**

- One-to-one: `Contact+Manager.swift:1305-1307` takes the key and writes the shortened record onto the model object. Everything that can throw comes after: `streamedParts` (`:1327`), `sealStreamed` (`:1382`), `seal` (`:1387`), `output.deliver` (`:1388`, `:1418`). The save at `:1390` is skipped on a throw, but the object is not put back and autosave is on.
- Group: `Contact+Manager.swift:1498-1511` says disabling autosave means "only the explicit save below can persist the pop". The `defer` turns autosave back on as the function exits, with the objects still changed. Any later save commits them, and until then `prekeyRecord(for:)` reads the changed object anyway.
- Group pass 1 throws part-way through its `map`: a card contact (`:1545`), an unreadable pairing (`:1546`), a member with no current key (`:1547` → `resolveKeyMaterial`, `:1724-1728`, which is every member revoked with `reset(identity:)`, `:748-763`), or `buildShardOperations` (`:1574`). Members mapped before the throw have already lost a key.

**Trace (no attacker needed)**

1. A group holds members A, B and R; R was revoked, so `currentKey` is nil.
2. Each Encrypt attempt maps A and B (one key taken from each, `:1550-1553`), then throws `contactHasNoKeys` at R.
3. After about 15 attempts A and B have no one-time keys of theirs left on this phone. One-to-one messages to A and B now go to the last-resort key ("Multiple Views · Temporary Key"), though nothing was ever sent to them.
4. With HC-1, a hostile member triggers the same drain on every attempt.

**Why existing guards don't stop it:** only `update(key:)` restores values and calls `rollback()` (`:721-739`); the send paths do neither.

**Confidence:** high for the one-to-one path and for the comment being wrong; medium for the revoked-member trigger, since I did not check whether the group compose screen blocks a group with a revoked member.

**Fix:** keep the sealed record as it was (`let before = contact.prekeyRecordEncrypted`) and restore it in a `catch` on both paths, or take the key into a local record and write it to the model only after the bundle is delivered. Correct the comment at `:1498-1509`.

**Test plan** (`.ambientTestKeyManager`, Simulator, no Enclave)

- One-to-one: a contact with inbound keys, `encryptBundle` with a `.file` output whose destination can't be written; after the throw, the record's inbound key count is unchanged. Fails today.
- Group: members with inbound keys plus one revoked member; `encryptGroupBundle` throws and the total inbound key count across the other members is unchanged. Fails today for whichever members are mapped first.

## 3. Hardening notes

- **Bug 194 is present at this commit for peers that send no `pairing` field.** `update(key:for:pairing:)` leaves the prekey record alone when `pairing` is nil (`Contact+Manager.swift:683`), so after a re-exchange with a 2.0.0 phone we keep sealing to the old phone's keys; without ML-KEM the old phone can open them. Recorded as Bug 194 (High) on `v2.1.0/bug-194-stale-inbound-prekeys`, and `bugs.md:14847` says every 2.0.x lacks the fix. Not a new finding, but it ships in 2.0.1 unless the drop is brought over.
- **Bug 173 (approving a hidden contact's challenge) is unchanged and its guard test is not on this branch.** `OccultaApp.swift:1023` and `:1135` still fetch the sender with no depth filter, and `approvePending` (`IdentityChallenge+Coordinator.swift:267-314`) signs and seals. `IdentityChallengeHiddenContactTests` is absent from `OccultaTests/IdentityChallenge/`.
- **`Coordinator.errorMessage` is never shown.** It is set at `IdentityChallenge+Coordinator.swift:210, 224, 235, 310` and read nowhere, so a challenge that fails to open and a response that fails to be produced are both silent. `endSession` (`OccultaApp.swift:562-577`) doesn't clear it either, which is harmless only while nothing reads it.
- **Clock before 1970 traps.** `UInt64(self.now().timeIntervalSince1970)` at `IdentityChallenge+Manager.swift:189, 302, 421` traps on a negative value. The ledger already uses `max(0, …)` (`IdentityChallenge+Ledger.swift:34`). Needs the device clock, so owner-only.
- **A failed `replenish` or final save discards an opened message whose one-time key is already gone.** `Contact+Manager.swift:2007-2012` and `:2398-2399` throw if the Enclave can't make a batch or the save fails, after the consume at `:1976` or in `openSlot`'s `defer`. The message can't be opened again. Catch the batch failure and retry on the next receipt.
- **`deleteContact` skips the checkpoint if the group purge throws.** `Contact+Manager.swift:558-571`: the empty prekey record is saved at `:558`, but `checkpointStore()` at `:571` is not reached when `:563-566` throws, so the old record with its Enclave blobs stays in the write-ahead log until the next unlock.
- **`reset(identity:)` keeps the whole prekey record** (`Contact+Manager.swift:748-763`): our own blobs for a revoked contact are never retired, so the sweep never deletes them. Nothing opens with them while the contact has no current key; Bug 194's fix covers the inbound side only.
- **`batchDigest`'s comment overstates.** `PairwiseDerivation.swift:74-88` writes lengths and the count with `UInt16(truncatingIfNeeded:)`, so "two different batches never encode alike" is false for a field of 65,536 bytes or more. I found no attack: each phone's own block is honest and short, and an encoding shorter than 65,536 bytes parses one way. Bound the sizes before hashing anyway.
- **`approvePending`'s task isn't tied to the session.** `IdentityChallenge+Coordinator.swift:270-313` sets `outboundShare` when biometrics finish, without checking that the session that showed the sheet is still open. I could not build a trace where the depth changes while the prompt is up, so this is a note.
- **The first failed check in the long-term challenge path consumes nothing, as intended.** `decryptSealed` skips `replenish` for a challenge (`:2006`) and `openIdentityBundle` reopens with the long-term key; I found no way to reach `handleAuthenticatedChallenge` without `openGroup`'s digest and signature checks (`:2333-2350`).

## 4. Test coverage gaps

- No test that `accept` rejects a key that isn't a curve point (HC-1); the helper used by every bookkeeper test builds non-points.
- No test that a failed send leaves the contact's inbound keys in place, for either path (HC-2).
- No test of a group send with a revoked or keyless member.
- No test of `Coordinator.approvePending` or of `route`'s error branches; `LAContext` blocks the first, nothing blocks the second.
- No test for a re-exchange without a `pairing` field leaving stale inbound keys (Bug 194's proposed guards are not on this branch).
- `IdentityChallengeHiddenContactTests` (Bug 173's guard) is missing here.
- No test that an opened message survives a failed `installFreshBatch`.
- No test for the identity-challenge manager with a clock before 1970.

## 5. Not covered

- `Docs/Features/Prekey Continuity/DESIGN.md` §8–§10, `FORWARD_SECRECY_GUIDE.md`, `forward_secrecy_flow.md`.
- `updateMaxVersion`, `resolveTargetVersion` and `bundleVersionState` (tier downgrade by a contact).
- Card paths that touch prekeys (`ContactManager+Cards.swift`: `openCardSlot`, `sendCardBundle`, `dropCardEraBatches`).
- The prekey-record migration (`PQmigration.swift:312-380`, `DatabaseMigration.carriedOverPrekeyRecord`) and the reseal of Enclave blobs (`KeyReseal+*.swift`).
- `PairingSlotKeys` (pair-key signing and verification for challenges) and `Crypto+Manager+GroupEncrypt.swift` outside `wrapRecipient`.
- `Exchange+Manager.swift` outside the lines listed; the exchange message parser.
- Whether the record's worst case fits `PrekeyRecordCodec.capacity`: I relied on the doc's budget and did not recompute it.
- Most of the test suite beyond the files named above.

# Shard Protocol Cases

Reference for every observable state transition in the manifest-based shard protocol.  
Actors: **Alice** = shard owner, **Bob** = trustee.

---

## Wire fields (per outbound `SealedPayload`)

| Field | Direction | Meaning |
|---|---|---|
| `shardOperations: [ShardOperation]?` | both | Data-carrying ops only: `.distribute`, `.replace`, `.handback` |
| `custodyManifest: [UUID]?` | trustee → owner | IDs of ALL shards trustee currently holds for this owner. `nil` = old build (no-op for receiver). `[]` = holds nothing. |
| `expectedShards: [UUID]?` | owner → trustee | IDs of shards owner expects trustee to hold. Absence of an ID is an implicit revoke signal for same-fingerprint shards. `nil` = old build. |

**Fingerprint** = SHA-256(owner's current X9.63 public key), stored sealed inside each `CustodyShard.Payload.ownerKeyFingerprint`.  
**Mismatch shard** = a `CustodyShard` whose stored fingerprint differs from Alice's current key fingerprint. Signals Alice lost her device.

---

## Case 1 — Normal distribution (happy path)

**Trigger:** Alice calls `prepareShards`, which calls `queueDistribute` and inserts `PendingShardDistribute` rows.

**Alice → Bob bundle:**
- `shardOperations: [.distribute(signedAttribute)]`
- `expectedShards: [id1]`

**Bob receives:**
1. `.distribute`: verifies signature, stores `CustodyShard(fingerprint: aliceFP, id: id1)`.
2. On `.distribute` with a new fingerprint: delete any mismatch-fingerprint shards for Alice (see Case 7).
3. `expectedShards`: delete same-fingerprint shards for Alice not in the list (none yet for a first distribute).

**Bob → Alice bundle (next outbound):**
- `custodyManifest: [id1]`

**Alice receives:**
- id1 in manifest → mark ShardRecord `.confirmed`, delete `PendingShardDistribute` row for id1.

**Retry:** Alice's distribute row persists until id1 appears in Bob's manifest. Every outbound bundle to Bob re-sends the `.distribute` op until confirmed.

---

## Case 2 — Distribution bundle lost in transit

**Setup:** Alice sends bundle with `.distribute(id1)`. Bundle never arrives at Bob.

**State:**
- Alice: ShardRecord `.pending`, `PendingShardDistribute` row exists.
- Bob: no `CustodyShard` for id1.

**Next Alice → Bob bundle:**
- `shardOperations: [.distribute(id1)]` (row still present → retried)
- `expectedShards: [id1]`

**Bob receives:** stores id1, next manifest includes id1.  
**Alice receives manifest with id1** → `.confirmed`, row deleted. ✓

---

## Case 3 — Replacement (PEK rotated, new shard supersedes old)

**Trigger:** Alice rotates entry PEK (content changed or manual redistribution). New shards are generated; `queueDistribute` is called with `oldAttributeID = oldID`.

**Alice → Bob bundle:**
- `shardOperations: [.replace(newAttr, replacesID: oldID)]`
- `expectedShards: [newID]`  ← `oldID` is absent

**Bob receives:**
1. `.replace`: stores `newID`, deletes `oldID` custody row.
2. `expectedShards`: `oldID` not in list → Bob would delete it — already gone from step 1. No-op.

**Bob → Alice bundle:**
- `custodyManifest: [newID]`

**Alice receives:** newID confirmed, `oldID` ShardRecord removed (superseded by new record). ✓

---

## Case 4 — Revocation (trustee removed without PEK rotation)

**Trigger:** Alice removes Bob as trustee from an entry. No new shard is distributed (threshold can still be met by remaining trustees).

**Alice action:** marks ShardRecord `.revoked` immediately (optimistic).

**Alice → Bob bundle (next outbound):**
- `expectedShards: []` or list that omits `id1`

**Bob receives:**
- `expectedShards` doesn't include `id1`, fingerprint matches Alice's current key → Bob deletes `CustodyShard` for `id1`. Silent, no response needed.

**Bob → Alice bundle:**
- `custodyManifest: []` (or list without `id1`)

**Alice receives:** id1 already `.revoked`, manifest absence is consistent. ✓

**If bundle to Bob is never delivered:** Bob still holds the shard indefinitely. This is safe — the shard reconstructs the correct PEK but Alice's entry is no longer shared with Bob (she has Alice's current PEK, just no recovery setup pointing to Bob). The shard is an orphan — cryptographically harmless, wastes storage only.

---

## Case 5 — Trustee sends manifest: shard confirmed

**Trigger:** Bob's app sends any outbound bundle to Alice.

**Bob → Alice bundle:**
- `custodyManifest: [id1, id2]`

**Alice processes:**
- id1, id2 in manifest and status is `.pending` → mark `.confirmed`, delete `PendingShardDistribute` rows.
- id1, id2 in manifest and status is already `.confirmed` → no-op.

---

## Case 6 — Trustee sends manifest: shard missing (Bob reinstalled)

**Trigger:** Bob reinstalls app (SwiftData wiped, SE key survives → fingerprint unchanged). Bob's manifest is now empty.

**Bob → Alice bundle:**
- `custodyManifest: []`

**Alice processes for each expected shard id1:**
- id1 absent from manifest AND manifest is non-nil (capable build) AND `PendingShardDistribute` row DOES NOT exist:
  - status was `.confirmed` → mark `.lost`.
  - status was `.pending` → mark `.lost` (distribute was never confirmed; Bob doesn't have it).
- id1 absent from manifest AND `PendingShardDistribute` row EXISTS → delivery in progress; no status change. Alice re-sends distribute on next bundle; Bob will receive it and manifest will include it.

**Recovery health:** entry degrades below threshold → Attention section shown. Alice redistributes.

---

## Case 7 — Owner key rotation (Alice gets a new device)

**Trigger:** Alice exchanges keys with Bob via UWB proximity. Bob's `ContactManager` updates Alice's contact with her new public key (new fingerprint). This fires `contactKeyRotated`.

**At this point:**
- Bob holds `CustodyShard` rows for Alice with `ownerKeyFingerprint = oldFP`.
- Alice has a new SE key (non-migratable). She doesn't know her old shard IDs.

**Bob → Alice bundle (next outbound, any content):**
- `shardOperations: [.handback(attr1), .handback(attr2)]` — all mismatch-fingerprint shards for Alice.
- `custodyManifest: [id1, id2]` — old shards still listed (Bob still holds them).

**Bob does NOT delete the mismatch shards immediately.** He keeps returning them on every bundle until Alice redistributes (see Case 8 for cleanup).

**Alice receives `.handback`:**
1. `acceptReturnedShard(attr)` → `ReconstructShard` buffer row inserted (sealed under recovery buffer key, no biometric needed).
2. If vault is locked: deferred — `tryFinalizeAllReconstructions` runs on next unlock.
3. If vault is unlocked: `tryFinalizeReconstruction(entryID:)` triggered opportunistically.

**Alice's `expectedShards` to Bob:**
- Alice is on a new device, knows no old shard IDs → `expectedShards: []`.
- Bob sees old IDs absent. But these are mismatch-fingerprint shards → Bob does NOT delete them based on `expectedShards`. Mismatch shards are immune to implicit revocation.

**Bob's mismatch shards survive** until Case 8 (Alice redistributes) triggers cleanup.

---

## Case 8 — Owner reconstruction complete, fresh distribution

**Trigger:** Alice collected ≥ k shards, `tryFinalizeReconstruction` succeeded, PEK re-wrapped. Alice redistributes to trustees.

**Alice → Bob bundle:**
- `shardOperations: [.distribute(newAttr)]` — new shard signed with Alice's NEW SE key.
- `expectedShards: [newID]`

**Bob receives `.distribute(newAttr)`:**
1. Stores `CustodyShard(fingerprint: newFP, id: newID)`.
2. **Cleanup trigger:** newFP ≠ oldFP for existing mismatch shards → delete all mismatch-fingerprint shards for Alice. Old handback cycle complete. ✓

**Bob receives `expectedShards: [newID]`:**
- All remaining same-fingerprint shards (if any) not in `[newID]` → deleted.

**Bob → Alice bundle:**
- `custodyManifest: [newID]` — only new shard listed.
- No more `.handback` ops — all mismatch rows gone.

**Alice receives:** newID confirmed. ✓

---

## Case 9 — Owner device loss: full recovery flow

**Precondition:** Alice lost phone. All vault content is gone. She has a new device.

1. Alice installs fresh Occulta. She has no contacts, no vault entries.
2. Alice re-exchanges with each trustee via UWB proximity (required for new key distribution).
3. For each trustee (Bob, Carol, Dave):
   - Trustee detects fingerprint mismatch → starts including `.handback` on every bundle.
4. Alice receives shards from each trustee via `.handback`.
5. Once ≥ k shards arrive: `tryFinalizeReconstruction` runs (vault must be unlocked):
   - Signature verification skipped (new SE key cannot verify old ECDSA sigs).
   - GCM authentication replaces ECDSA as integrity check.
   - PEK reconstructed, re-wrapped under new vault key.
6. Alice redistributes new shards to all trustees (Case 8).
7. All trustees' mismatch shards deleted on receiving the new `.distribute`.

**Note:** SSS recovers the PEK only. If Alice also lost her vault backup (encrypted content), full recovery is impossible. See VAULT_SSS_GUIDE.md "Recovery scope".

---

## Case 10 — Trustee device loss (Bob loses phone)

**Trigger:** Bob reinstalls. His `CustodyShard` table is empty. SE key survives.

**Bob → Alice bundle:**
- `custodyManifest: []`

**Alice:** sees id1 absent from non-nil manifest, status `.confirmed`, no distribute row → marks `.lost`.

**Recovery health** degrades. Alice redistributes to Bob or a new trustee.

**Alice → Bob bundle (redistributed):**
- `shardOperations: [.distribute(id2)]` (new shard for Bob)

**Bob receives:** stores id2, manifest includes id2.  
**Alice:** id2 confirmed. ✓

---

## Case 11 — Both Alice and Bob lose their devices simultaneously

- Bob's mismatch shards are gone (reinstall).
- Alice exchanges with Bob → Bob detects fingerprint mismatch, but has no shards to return.
- Bob's manifest: `[]`.
- Alice never receives a `.handback` from Bob.
- If Alice collected ≥ k shards from OTHER trustees: reconstruction succeeds. Bob is simply one of the missing shards — below-threshold if Bob was critical to meeting k.
- If Alice needed Bob's shard to meet k: reconstruction fails. Alice's entry is unrecoverable without a vault backup.

---

## Case 12 — Old-build trustee (no manifest support)

Bob's app does not know about `custodyManifest` or `expectedShards`.

**Bob → Alice bundle:** no `custodyManifest` field (`nil` on decode).  
**Alice processes:** `nil` manifest → no status update. ShardRecord stays `.pending` or `.confirmed` (stale).

**Alice → Bob bundle:** `expectedShards` field present, but Bob ignores unknown JSON keys.  
**Bob:** no deletion of stale shards (doesn't understand `expectedShards`).

**Implication:** status reconciliation stalls until Bob upgrades. Core shard delivery (`.distribute`, `.handback`) still works — those op kinds existed before manifests.

---

## Case 13 — Vault locked when `.handback` arrives

**Scenario:** Alice's vault is locked when Bob's bundle with `.handback` arrives.

**Processing:**
1. `ShardCustodyManager.handleInbound` dispatches `.handback` → `acceptReturnedShard`.
2. `acceptReturnedShard` inserts `ReconstructShard` row under recovery buffer key (device-unlock, no biometric). ✓
3. `tryFinalizeReconstruction` is called but returns immediately (vault locked).
4. `ReconstructShard` row persists.

**On next vault unlock:**
- `tryFinalizeAllReconstructions()` sweeps all entries. If threshold met → reconstruction succeeds.

---

## Case 14 — Vault locked when manifest arrives

**Scenario:** Alice's vault is locked when Bob's bundle includes `custodyManifest: [id1]`.

**Processing:**
1. `ShardCustodyManager.handleInbound` calls `processInboundManifest`.
2. `updateShardStatus` is called → throws `.locked`.
3. A `PendingShardStatusUpdate` row is queued.
4. On next unlock: `drainPendingShardStatusUpdates()` replays the update.

---

## Case 15 — Duplicate `.distribute` delivery

**Scenario:** Alice sends the same shard twice (retry scenario, idempotency check).

**Bob receives second `.distribute(id1)`:**
- `handleDistribute` checks: does a `CustodyShard` with `signedAttribute.id == id1` already exist?
- Yes → skip insert. The shard is already stored correctly.
- Bob's next manifest includes id1 either way.

**Alice:** distribute row deleted when manifest confirms id1 (first or second delivery). ✓

---

## Case 16 — Tampered shard (signature verification)

**Scenario:** A malicious actor intercepts a `.distribute` bundle and replaces shard bytes.

**Bob receives tampered `.distribute`:**
- `handleDistribute` calls `attribute.verify(against: senderPublicKey)`.
- ECDSA verification fails → `throw CustodyError.signatureRejected`.
- No `CustodyShard` inserted.
- Bob's manifest never includes the tampered ID.

**Alice:** ShardRecord stays `.pending`. Distribute row persists → keep retrying.

**On new device (no SE key):** signature verification skipped. If the shard bytes were altered, `reconstructEntry` attempts decryption → GCM authentication tag rejects the garbage PEK → `VaultError.decryptionFailed` thrown. No plaintext exposed.

---

## Case 17 — Below-threshold reconstruction attempt

**Scenario:** Alice calls `tryFinalizeReconstruction` with fewer than k shards in the buffer.

- Guard: `mine.count >= meta.threshold` → false → return immediately.
- Buffer rows intact. Alice waits for more `.handback` bundles.

---

## Case 18 — `expectedShards` arrives while distribute is in flight

**Scenario:** Alice queues distribute for id1 (row exists), sends bundle to Bob. Separately, Alice sends a bundle with `expectedShards: [id1]` before Bob's manifest arrives.

**Bob receives `expectedShards: [id1]`:**
- id1 IS in the expected list → no deletion. ✓
- If Bob has id1 already stored: manifest in reply will include it.
- If Bob doesn't have id1 yet (distribute hasn't arrived): distribute arrives later (retry), Bob stores it, manifest then includes it.

---

## Case 19 — ShardRecord.revokePending (legacy)

Existing serialized data may contain `.revokePending` status. On decode this is valid.  
New code never sets `.revokePending` — revocation marks `.revoked` immediately (optimistic).  
Shards with `.revokePending` status from old data are treated the same as `.revoked` for threshold calculations: not counted as active.

---

## Health-check rules

| Alice observes | Condition | Action |
|---|---|---|
| ID in manifest | any status | mark `.confirmed`, delete PendingShardDistribute row |
| ID NOT in manifest | manifest non-nil AND PendingShardDistribute row exists | delivery in progress; no change |
| ID NOT in manifest | manifest non-nil AND no distribute row AND status ∈ {.pending, .confirmed} | mark `.lost` |
| ID NOT in manifest | manifest is `nil` | no update (old-build Bob) |
| ID NOT in manifest | status is `.revoked` or `.lost` | no change (already terminal) |

**Recovery health recompute triggers:** vault unlock, `prepareShards`, `updateShardStatus`, `deleteEntry`.  
**Active shard count:** status ∈ {`.pending`, `.confirmed`} only. `.lost`, `.revoked`, `.revokePending` are inactive.

---

## Bob's deletion rules for `expectedShards`

| Condition | Action |
|---|---|
| Shard fingerprint == Alice's current fingerprint AND id NOT in expectedShards | Delete CustodyShard |
| Shard fingerprint ≠ Alice's current fingerprint (mismatch) | No deletion; keep returning via `.handback` |
| Alice sends `.distribute` with NEW fingerprint | Delete all mismatch-fingerprint shards for this contact |

---

## Invariants

1. A `CustodyShard` with fingerprint mismatch is NEVER deleted by `processExpectedShards`. It is only deleted when Alice distributes a new shard with her new fingerprint.
2. A `PendingShardDistribute` row is deleted ONLY when the shard ID appears in Bob's `custodyManifest`. It is not deleted on send.
3. `.handback` is included in every outbound bundle to Alice as long as any mismatch-fingerprint custody shard exists for her.
4. `.distribute` is included in every outbound bundle to Bob as long as the `PendingShardDistribute` row for that shard exists.
5. Old builds that receive `custodyManifest` or `expectedShards` fields ignore them silently (unknown JSON keys).

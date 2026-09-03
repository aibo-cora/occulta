# Vault-Key-Gated Storage — Vault Entries and the BEK Record

**Status:** design, not built. One sub-decision settled, rest open. **Owner entries:**
`Docs/Features/Secure Mode/bugs.md` Bug 102 (BEK), Bug 105 (its sharpest evidence); `forensic-trace-
avoidance.md` S5 (contacts), S8 (vault entries). **Compiled:** 2026-09-02, split out of
`STORAGE_LAYERING.md` once that doc's own container analysis showed this half and
[`RECOVERY_BUFFER_LAYERING.md`](RECOVERY_BUFFER_LAYERING.md) are independently buildable — see §7 for
exactly where they do and don't touch.

**What this is.** Everything about the container sealed under the vault's biometric-gated key: sensitive
vault entries (if built) and the BEK record. Contacts (S5) aren't stored here — they use the existing,
separate Secure-Mode-keyed `LayerStore` — but their build is the recommended pilot for the lifecycle
this container's vault-entry half needs, so it's tracked here rather than a third document.

---

## 1. Why this is needed

**Recovery is device-wide, and so is most other sensitive storage, in an app that layers
*classification* almost everywhere else.**

Contacts, vault entries, group membership, PIN gates, and the layer arrays are all depth-partitioned
at the classification level — a `visibleThroughDepth` stamp gates what's shown. But the underlying
*storage* mostly isn't: one `BackupEncryptionKey` row, device-wide; live SQLite rows with plaintext row
counts and timestamps for both sensitive contacts (S5) and vault entries (S8). The classification layer
says what a session may see; underneath it the same bytes and row counts sit there for anyone who
reaches the raw storage.

**The evidence is the shape of every fix so far.** Across 2026-08-26/27 the restore flow alone was
patched five times — uniform confirmation prompt, uniform banner, deleted acknowledgment, filler
padding on shard ops, shards moved out of a length-leaking file. Every one of those flattens a
*symptom*. None removes it. Two were later found to have introduced a new tell while closing an old
one — the signature of patching a structural problem at the surface.

---

## 2. What is and is not layered today

| Thing | Scope | Consequence |
|---|---|---|
| Sensitive contacts (S5) | `visibleThroughDepth` + UI filter classify; rows stay live, readable under the canonical DB key | a raw SQLite read on an unlocked device sees every sensitive contact regardless of depth |
| Vault entries (S8) | `visibleThroughDepth` (exact-match) classifies, stamped at activation Step 8; `id`/`createdAt` are plaintext columns | row count and creation timestamps are identical at every depth — not depth-gated at all |
| Restored vault entries | **per depth** — `importBackup` stamps `visibleThroughDepth`, exact-match | contents are correctly contained (this part already works) |
| `BackupEncryptionKey` | one row, device-wide, no depth stamp | a restore completing in duress installs the device's real backup key |
| `shardMetadata` | inside the BEK payload, so device-wide | the trustee list is shared across layers |
| Shard *distribution* | no depth gate at all | **a duress layer can distribute shares of the real BEK — see §6** |

`shardMetadata` is distribution *bookkeeping* (who has a share, its status) — it does not hold shard
values. Restore-side shard collection is a different container; see `RECOVERY_BUFFER_LAYERING.md`.

---

## 3. What already exists — and it is most of the mechanism

`LayerStore` (`SecureMode+LayerStore.swift`, `LayerStore.md`) is already a per-depth fixed-width
container, shipped, currently holding sensitive contacts:

- **32 slots**, tied to `AppLayerConfig.maxVerifierCount` so file size and verifier-array length leak
  no more than each other. One slot per activation layer, assigned via `sealedBlobSlots`.
- **`slotPlaintextSize = 32 KB`, fixed.** Every slot — real payload or random filler — seals to
  exactly that length, so the file is always `32 × (32 KB + 28)` bytes regardless of contents.
- **Eagerly created**, from first launch, before Secure Mode is ever configured. No header, no magic
  bytes, no version field, no slot count. Indistinguishable from a vault backup.
- **Full regeneration on every write** — all 32 slots re-sealed with fresh nonces, so padding slots
  cannot be identified by diffing two versions of the file.
- **Capacity is already enforced and already surfaced.** `push` throws `.payloadTooLarge` before any
  I/O, and `estimatedSize(for:)` drives a live capacity indicator in the contact classification UI
  (`SecureModeSetupFlow`) — the user sees the budget as they spend it rather than hitting a wall at
  commit time.

That last point answers "we should not impose caps, we need graceful flexibility." A fixed envelope
isn't negotiable — it's what makes an occupied slot indistinguishable from an empty one. What *is*
negotiable is whether the user can see the budget as they spend it; this codebase already chose "yes"
for contacts.

**What `LayerStore` deliberately does not hold:** vault per-entry keys, prekeys, or `CustodyShard`
records — see §4 for why the first of those is load-bearing.

---

## 4. The protection domains

`LayerStore.md` excludes vault per-entry keys deliberately: *"Storing them would widen the attack
surface since a store compromise requires only the SE Secure Mode key, bypassing the biometric gate
that otherwise protects vault content (Bug 8)."* Verified in `Key+Manager.swift` rather than taken from
prose — three domains, not two, and this is why this container exists separately from both
`LayerStore` and `RECOVERY_BUFFER_LAYERING.md`'s container:

| Key | Derived by | Biometric gate | Seals today |
|---|---|---|---|
| Secure-Mode key | (existing) | No | Contact `LayerStore`, local DB key |
| **Vault key** | `deriveVaultKey(context: LAContext)` | **Yes** | Vault entry content (`VaultManager.currentKey()`) — **and the BEK record itself, per §5's table** |
| Recovery buffer / shard custody key | `deriveRecoveryBufferKey()` — no `LAContext` | No | `CustodyShard`, shard buffer, restore/arming state — see the other doc |

**Putting vault entries into the existing Secure-Mode-keyed store would collapse the first two domains
and strictly downgrade vault protection.** It's also why S8 is rated below S5: a duress-PIN-only coercer
cannot open the vault at all, so the row-count tell needs duress PIN *and* forced biometrics to be
reachable — see §4a for why that bar may be lower than it looks for this app's actual threat model.

**Not only a cold-disk risk.** A coercer who compels biometric auth causes `deriveVaultKey` to hand the
derived `SymmetricKey` to the app process, in ordinary memory, for the duration it's used. Extracting
it needs forensic tooling — jailbreak plus debugger, or GrayKey/Cellebrite-class extraction — not a
break of the Enclave; the private key never leaves it. But this project's own threat model already
assumes exactly that capability for the local DB key (`forensic-trace-avoidance.md` S1). With the vault
key alone, a coercer at depth 2 could in principle decrypt every other slot in *this* container,
including `shardMetadata` — trustee counts and identities — at depths they were never meant to see.

### 4a. Is "duress PIN + forced biometrics" actually the high bar S8 assumes? — unverified claim, not a finding

Raised as a question, not settled here. S8's downgrade rests on that compound attack being harder than
PIN coercion alone. The counter-argument — that biometric unlock is compellable under a lower legal bar
than a memorized PIN in some jurisdictions, so the compound attack may be closer to the default
coercion pattern than a stacked edge case for this app's stated threat model — is a **legal claim**,
not a technical one, and has not been checked against actual counsel or jurisdiction-specific sourcing.
Route it through the same counsel pass `Docs/Audit/OPEN_LIMITATIONS.md` Section E already queues for
duress/coercer language; don't treat it as established reasoning on the strength of sounding plausible.
What *is* verified, independent of this claim: the failure mode itself — the UI showing "No entries
yet" while the raw DB holds N rows — is real regardless of how the legal question resolves.

---

## 5. Target design

**One fixed-width array of fixed-count slots, one slot per depth**, sealed under the vault key. Each
slot carries, as separately sealed fields:

| Field | Notes |
|---|---|
| BEK record | `bekBytes`, `distributionID`, `shardMetadata` — capped and padded, see §8 |
| Sensitive vault entries (if built) | canonical copy; DB rows become unreadable shells |

**Two record types don't force two containers.** Preserving a sealed field never requires its own key —
one array is fewer artifacts to pad, clean up, and explain than one per feature.

**Every sealed field's AAD must bind its slot index.** Without it, lifting slot 2's ciphertext into
slot 0 moves a duress layer's BEK — or vault entries — into the real one.

**This container cannot get cryptographic per-depth separation for free.** The vault key is not
depth-derived, and making it so touches every vault entry. §8 item 4 has the remedy and its two
applications.

**Where it lives:** a `LayerStore`-shaped sibling file, not `AppLayerConfig` — that row is read on
essentially every security check and SwiftData loads the whole row, so bulk payloads would ride along
with every `requireConfig()`. Eagerly created from first launch, same reasoning as §3.

---

## 6. Bug 105 — the sharpest evidence, and the one item with a clock on it

**Filed 2026-08-28, found while scoping this design — Open, High severity, reachable on shipped code
with no attacker-supplied file, no shard delivery, and no restore.**

`prepareBEKShards` has no depth gate — it reads the one device-wide BEK via `fetchDecodedBEK`, and
`Vault+ShardSetup.swift` contains zero references to `currentDepth` or `isVisible`. The trustee
*picker* is correctly filtered (`mlkemEligibleContacts` applies `isVisible(atDepth:)`), which is
exactly what makes this easy to miss: the contacts are per-layer, the key they are handed shares of is
not.

So at a duress depth, through ordinary UI and with no attacker-supplied file and no shard delivery, a
coercer can distribute shares of the owner's **real** backup key to his own phones. Two harms:

- He holds threshold shares of the real BEK. Latent until he obtains any `.occbak` — via a device
  backup, iCloud, or Bug 101's `Documents/Inbox` copy (see the other doc).
- Immediate: `prepareBEKShards` reuses the existing `distributionID` and **overwrites**
  `shardMetadata`, so the owner's real trustee list is replaced by his. Genuine trustees still hold
  valid shares, but the device's record of who holds what is gone.

This is the cleanest demonstration of §1's thesis, because every step is legitimate app behaviour. It
also answers open decision §8 item 1 empirically: a duress layer can distribute today, and it
distributes the real key.

**Its short-term remedy is genuinely unattractive**, which argues for this design rather than against
fixing it now: refusing distribution above depth 0 closes the harm but adds an observable difference
between layers — the trap two fixes already fell into the same week.

**What actually closes it: only stages 1 and 2 of §7 — entirely within this container.** Its own
remedy is specific — *"once each layer holds its own BEK, distributing at a duress depth distributes
that layer's key to that layer's contacts."* `prepareBEKShards` needs no change; it already calls
`fetchDecodedBEK` internally, so once that's depth-routed the fix is automatic. Not needed to close
this bug: anything in `RECOVERY_BUFFER_LAYERING.md` (the restore side — Bugs 99/93/95's territory), or
item 4's convention-vs-cryptography hardening (the baseline fix works fine with today's code-discipline
separation).

**Shard tracking comes along for free.** `ShardDistributionMetadata` (threshold + `[ShardRecord]`,
`Vault+Model.swift:80-100`) lives entirely inside `BackupEncryptionKey.Payload.shardMetadata` — not a
separate SwiftData table. `bekSetupState` and `bekShardMetadata()` are pure computed properties over
whatever `fetchDecodedBEK` returns, so once that's depth-routed both become depth-correct without
either function changing. (`PendingShardDistribute`/`queueDistribute` looked relevant but isn't — a
separate queue used only for per-entry vault PEK shares; BEK distribution builds and returns bundles
synchronously and never touches it.) Item 2's trustee-count padding is the one piece this doesn't give
for free — `shardMetadata`'s variable length still needs its own cap.

---

## 7. Build stages, and where they touch the other container

| # | Stage | Verify | Touches `RECOVERY_BUFFER_LAYERING.md`? |
|---|---|---|---|
| 1 | Slotted BEK array here, seeded with filler at first launch. Migrate the single `BackupEncryptionKey` row into slot 0 | array length identical whether 0 or 32 depths hold a BEK; existing export/import tests pass against slot 0 | No |
| 2 | Route BEK access by depth — `fetchDecodedBEK`, `setupBEK`, `currentBEK`, `bekSetupState`, `bekShardMetadata`, `exportBackup`, `reconstructBEK` | a BEK created at depth 2 is invisible at depth 0 and vice versa | No |
| — | Vault entries: contacts' Design B first (§8 candidates), then this container's own entry-shell lifecycle | see §8 | No |
| 5 | Completion per layer | a restore armed at depth N completes at N and nowhere else | **Yes — the only join point.** Reads collected shares from the other container, writes the reconstructed BEK into this one's slot |

**Acceptance criterion for the whole design (both containers):** a coercer can arm, set up his own
trustees, collect and complete a restore in his layer, and see exactly what a working app does —
because it *is* a working app in that layer, not a simulation of one.

**A large change for a patch release.** Ships in **v1.10.3**, on `v1.10.3/bek-layering-refactor` off
`release/v1.10.3`. Full migration/release-scope reasoning, including the legacy-row tombstone this
container's Stage 1 needs, is in §9.

---

## 8. Open decisions

1. **Per-depth shard distribution — settled 2026-09-02.** Does each layer carry its own trustee set?
   May a duress layer distribute at all? What does a trustee see when holding shards for two of the
   owner's layers? Resolved without new design:
   - **Own trustee set per layer: yes, for free.** `shardMetadata` becomes per-depth automatically once
     the BEK is slotted. The contact picker feeding `prepareBEKShards(threshold:recipients:)`
     (`Vault+Manager+Backup.swift:368`) already filters by `isVisible(atDepth:)`. The key itself was the
     only device-wide thing — Bug 105's exact finding.
   - **Duress-layer distribution: allowed uniformly at every depth.** Refusing it above depth 0 is a
     depth-conditional behavior — the same trap two other fixes fell into the same week. Once the BEK
     is depth-scoped, distributing at depth N distributes depth N's own decoy key — nothing left to
     leak.
   - **Same trustee holding shards for two layers: already handled, nothing depth-aware needed on the
     trustee side.** `visibleThroughDepth` is a ceiling (`value >= depth`), so a contact visible at both
     depth 0 and depth 2 is the normal case. `CustodyShard` stores shards keyed by an opaque row id with
     no contact linkage in plaintext, and already tolerates multiple live shards from one owner.
   Net: nothing new to build for this decision — a consequence of the design above plus the existing
   trustee model.

2. **The container's overall slot budget.** Two payload types now compete for it (vault entries, BEK
   record), not one. 32 KB (`LayerStore`'s existing constant) holds ~30 contacts with ML-KEM material;
   both vault entries and a BEK record are far smaller, so 32 KB is a generous starting point — but
   must be picked against §10's tripwire, and only matters once §6's build order reaches vault entries.

3. **A trustee-count cap for `shardMetadata` — found 2026-09-02, not previously named.**
   `ShardDistributionMetadata.shards: [ShardRecord]` is variable-length, one record per trustee.
   `prepareBEKShards`/`distributeBEKShards` bound `recipients.count` at nowhere today. Different depths
   will legitimately have different trustee counts — a duress layer never set up for backup has zero.
   Unpadded, that's a length leak of the same shape closed elsewhere in this design: a near-empty
   `shardMetadata` compresses shorter than a full one, before the container's outer padding gets a
   chance to hide it. A realistic cap (5–10 covers any real Shamir threshold use — the cryptographic
   ceiling, confirmed in `ShamirSecretSharing.swift`, is 255 shares via `UInt8` x-coordinates, far past
   what's relevant) also firmly bounds the BEK record's worst case for item 2's budget.

4. **Convention or cryptography for the BEK field's slot separation** (Bug 92) — splits into two
   applications with different blockers and costs:

   **Why not a slow KDF.** `PIN+Manager.swift`'s existing verifier derivation is
   `HKDF(seKey, info: label ∥ pin)` — deliberately fast. `plan.md` records PBKDF2 being tried for this
   exact purpose and removed: *"on-device code execution defeats any KDF regardless of iteration
   count... SE key prevents all off-device attacks"* doing the actual work instead. Binding derivation
   to the SE key removes the offline-brute-force attacker entirely; the same shipped pattern fits here
   too, not a new primitive.

   **The live slot — looks buildable now.** Binding each slot's key to that depth's own PIN, the same
   way verifiers already are, closes the vault-key-extraction risk in §4: a session at depth 2 only
   ever holds depth 2's PIN, so it can't derive depth 0's slot key even with the vault key in hand.
   Touches only local storage — doesn't touch Shamir reconstruction or restore UX on a fresh device.

   **The exported `.occbak` file (Bug 92's original proposal) — same mechanism, real recovery-contract
   cost, decide separately.** Folding the PIN into the file's wrapping key means a restorer needs both
   the reconstructed `bekBytes` and the PIN active at export time — shards alone stop being sufficient,
   and rotating a PIN orphans old exports. This half touches `RECOVERY_BUFFER_LAYERING.md`'s territory
   (the exported/pending backup contents), not this container.

**Vault entries and contacts (S5/S8) — candidates, decided 2026-09-02 by the release owner:** build
both, S5 (contacts) before S8 (vault entries). Contacts' Design B is already specified and deferred —
unreadable shells in the DB, existing `LayerStore` blob is the canonical copy, loaded to memory on
unlock, wiped on lock — no new file or key, four named steps. Vault entries reuse the identical
lifecycle in this container instead of the existing one, once built once on the cheaper case. §4a
stayed unverified throughout and was not the basis for this decision.

---

## 9. Migration and release scope

Settled 2026-08-28.

**Release scope.** Ships in **v1.10.3**, branch `v1.10.3/bek-layering-refactor` off `release/v1.10.3`
— not a separate `develop` branch, since `develop` was 133 commits behind at the time and would have
dropped every fix this design builds on. (Both branches have since merged; no longer diverging.) The
patch framing is deliberate: Bug 105 is live, and its standalone remedy is the unattractive one in §6.
Cost: a patch version implies downgrade is safe, and after this migration it is not.

**Compatibility.** New build reads old data — free, `BackupEncryptionKey.Payload` is `Codable`, fields
added as optional decode against existing ciphertext untouched. Old build reads what the new build
wrote — impossible for slot 0 by construction; an old build only keeps working if the device-wide row
still holds the real key, which is Bug 105 itself. The conflict is narrowed to only slot 0's BEK bytes
— everything else (sibling files, the visibility gate, the cap) is additive and downgrade-tolerant.
**Add a `formatVersion` byte** to the new file's sealed plaintext — `ExportMetaSlotCodec` has none, a
gap worth not repeating.

**Tombstone the legacy row — do not delete it.** When slot 0's BEK moves into the slot file, keep the
`BackupEncryptionKey` row and overwrite `encryptedPayload` with same-length filler. Deleting it is
itself a new tell. A filler-filled row is indistinguishable from a real one on cold disk. More
importantly, a downgraded build then fails closed at three of four sites (`setupBEK` no-ops on row
presence; `currentBEK` throws; `reconstructBEK` propagates decrypt failure) — the fourth,
`storePendingRestore`, is the soft spot tracked in `RECOVERY_BUFFER_LAYERING.md` §8, since arming a
restore is that container's action even though the check reads this container's tombstoned row.

**Rejected alternatives:** dual-run (legacy restores finish under legacy rules) — attacker-pinnable, a
coercer who arms before updating keeps every pre-design weakness; complete-then-migrate — strictly
worse, gated on an event a coercer can indefinitely prevent (Bug 99); keep depth 0's BEK in the legacy
row, slot only depths ≥1 — genuine downgrade safety, but reintroduces the "slot count must never vary"
leak in a different shape.

---

## 10. Tripwire

`VaultEntryType` has `document` and `photo` **commented out**. The whole fixed-slot design, in both
containers, rests on a vault backup being kilobytes. Enabling either makes the vault bulk data and
invalidates this container's design entirely. That enum is the place to notice, so the constraint
belongs as a comment there too.

---

## See also

[`RECOVERY_BUFFER_LAYERING.md`](RECOVERY_BUFFER_LAYERING.md) — the shard buffer, restore/arming state,
and `CustodyShard`. Independent of this document except at §7 Stage 5 (completion) and §9's
`storePendingRestore` soft spot, both noted at their point of contact above.

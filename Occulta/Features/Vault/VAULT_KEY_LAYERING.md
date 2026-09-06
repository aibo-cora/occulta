# Vault-Key-Gated Storage — Vault Entries and the BEK Record

**Status:** design complete, nothing built. All five items in §8 decided (item 2 deferred by design,
not urgent until vault entries are actually built). **Owner entries:** `Docs/Features/Secure Mode/
bugs.md` Bug 102 (BEK), Bug 105 (its sharpest evidence); `forensic-trace-avoidance.md` S5 (contacts),
S8 (vault entries). **Spec docs this changes:** [`VAULT_BACKUP_GUIDE.md`](VAULT_BACKUP_GUIDE.md),
[`VAULT_SSS_GUIDE.md`](VAULT_SSS_GUIDE.md) — both describe the device-wide BEK/shard behavior this
design replaces; see their own "Secure Mode" closing sections, which point back here. **Compiled:**
2026-09-02, split out of `STORAGE_LAYERING.md` once that doc's own container analysis showed this half
and [`RECOVERY_BUFFER_LAYERING.md`](RECOVERY_BUFFER_LAYERING.md) are independently buildable — see §7
for exactly where they do and don't touch. Last decision recorded: 2026-09-06.

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

**Found 2026-09-05, not yet decided how far to take it: no dedicated directory, no magic byte —
disambiguate by which key opens it.** Checked the existing precedent directly
(`AppGroupLayerStoreBackend.swift:26-53`) rather than assume: the current contact blob already lives in
its own dedicated directory (`"blobs"`), holds nothing else, and `findFile(in:)` just reads whatever
single file is there — filename is a fresh UUID on *every* write, old file deleted only after the new
one lands, no magic byte, no stored path. That's most of the way there, but the dedicated directory
itself is a residual signal: an examiner who has read this app's source sees a purpose-named folder and
learns "a concealment subsystem lives here" from structure alone, before touching a single byte. Once
this container and `RECOVERY_BUFFER_LAYERING.md`'s exist alongside it, that becomes two or three
purpose-named folders — architecture leaking through directory layout, not content.

**The stronger version:** one shared, undifferentiated pool for all of them — same directory, same
random-renamed-on-every-write naming, same fixed size (§8 item 3's cross-container sizing note) —
disambiguated purely by
which of the app's own keys successfully opens a given file via `AES.GCM.open`. No magic byte required;
GCM's own authentication tag already distinguishes "wrong key" from "right key" for free, which is a
cleaner signal than a magic byte would be anyway, since a magic byte is plaintext-visible before any
key is involved at all. Cost is a handful of trial decryptions per lookup — computationally trivial for
a fixed, small key set (vault key, recovery-buffer key, Secure-Mode key). Pool file *count* must stay
fixed regardless of configuration, matching the eager-creation principle already used everywhere in
this design, so count doesn't become a new signal in place of the directory-name one it replaces.

Not yet decided how far to take this — folding the recovery-buffer container and the existing contact
blob into the same pool as this one requires `RECOVERY_BUFFER_LAYERING.md`'s own "where it lives"
section to adopt the same approach, which it doesn't yet.

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
   must be picked against §11's tripwire, and only matters once §6's build order reaches vault entries.

3. **A trustee-count cap for `shardMetadata` — found 2026-09-02. Cap number agreed (10); wire
   format and the pre-existing-data question below are what's still open.**

   `ShardDistributionMetadata.shards: [ShardRecord]` is variable-length, one record per trustee, and
   `prepareBEKShards`/`distributeBEKShards` bound `recipients.count` nowhere today. Different depths
   legitimately have different trustee counts — a duress layer never set up for backup has zero — so
   unpadded, a near-empty `shardMetadata` compresses shorter than a full one, before the container's
   outer padding gets a chance to hide it.

   **Cap = 10.** Comfortably above any realistic Shamir trustee count (consumer social-recovery schemes
   typically run 3–9 guardians) while keeping padding cost negligible in this container. The
   cryptographic ceiling — confirmed in `ShamirSecretSharing.swift`, `UInt8` x-coordinates — is 255
   shares and was never the number this was sized against.

   **Wire format — fixed-byte binary, not JSON/`Codable` as `Payload` is today.** A first pass at this
   used `Payload`'s existing `Codable` shape plus a computed pad-to-target step, which turned out to be
   the wrong instinct: `ShardStatus`'s `String` rawValues alone run 4–13 characters
   (`"lost"` vs. `"revokePending"`), a 9-byte-per-record spread that a JSON-encode-then-pad approach
   would have to bound correctly by hand and re-verify every time a case is added or renamed — exactly
   the kind of thing that quietly breaks later. Fixed byte offsets close this structurally instead of
   by computation. Per-trustee `ShardRecord`:

   | Field | Bytes | Encoding |
   |---|---|---|
   | `contactIdentifier` | 16 | raw UUID bytes, not the 36-char string |
   | `attributeID` | 16 | raw UUID bytes |
   | `status` | 1 | `UInt8` tag, not the enum's string rawValue |
   | `distributedAt` | 9 | 1 presence byte + 8-byte `UInt64` epoch seconds, always both, zero-filled when absent — **never 8 bytes when absent and 9 when present; that byte-count difference is itself the leak** |
   | **Total** | **42** | — |

   **Storage capacity and write policy are two different numbers — settled 2026-09-05.** The array's
   *storage* capacity is **255**, the Shamir ceiling itself (`UInt8` x-coordinates,
   `ShamirSecretSharing.swift`) — not an arbitrary "generous" guess, the literal hardware/math limit of
   what could ever exist, since the library itself refuses to produce more. `prepareBEKShards`'s
   *write-time guard* still enforces **10** for anything new or redistributed. These don't need to
   match, and forcing them to would recreate the exact problem below.

   `Payload` overall, at capacity: `formatVersion` (`UInt16`, 2) + `bekBytes` (32) + `distributionID`
   (16) + `threshold` (1, `UInt8` comfortably covers 2–255) + shards array (`42 × 255 = 10,710`) =
   **10,761 bytes plaintext, always** — every slot, every device, whether it holds 0 real records or
   255, regardless of write-time policy. This changes `Payload`'s encoding project-wide, not just
   `shardMetadata` — worth noting against §5's table, which doesn't currently specify one.

   **Why 255 and not 10: the over-cap question this resolves.** A legacy distribution created before
   any cap existed could hold any count up to Shamir's own limit. Sizing storage to the *write* policy
   (10) would mean Stage 1's migration literally cannot represent a legacy distribution larger than
   that — no fixed-width encoding is at fault here, there'd just be nowhere to put the 11th record.
   Sizing to 255 makes that scenario impossible by construction rather than needing a remedy: a legacy
   distribution of any size Shamir could ever have produced fits, unconditionally, forever. Nothing is
   truncated, nothing is silently reduced, no trustee is ever dropped without the owner choosing it —
   reading and reconstructing an over-cap legacy distribution is permanently unaffected. The only
   consequence: redistributing or updating one is still capped at 10 by the write guard, same as any
   fresh distribution — reduce first if there's ever a reason to change it. This was framed as two
   options (A/B) before working through the actual numbers; it isn't a tradeoff once the true ceiling
   (255) turns out to cost only ~10.5 KB either way.

   **Measured, not estimated — real `JSONEncoder()` output for today's `Codable` scheme, same encoder
   the codebase actually uses (`Vault+Manager+Backup.swift:1016`), against the fixed design above:**

   | Trustees | Current (JSON) — best case¹ | Current (JSON) — worst case² | New design, fixed-width³ |
   |---|---|---|---|
   | 0 | 159 → ciphertext 187 | 159 → ciphertext 187 | 10,761 → ciphertext **10,789** |
   | 5 | 808 → ciphertext 836 | 1,018 → ciphertext 1,046 | 10,761 → ciphertext **10,789** |
   | 10 | 1,459 → ciphertext 1,487 | 1,877 → ciphertext 1,905 | 10,761 → ciphertext **10,789** |
   | 255 | 33,310 → ciphertext 33,338 | 43,988 → ciphertext 44,016 | 10,761 → ciphertext **10,789** |

   ¹ Every `distributedAt` nil — Swift's synthesized `Codable` uses `encodeIfPresent`, so a nil optional
   omits the key entirely rather than writing `null` — and every `status` the shortest rawValue
   (`"lost"`, 4 chars). ² Every `distributedAt` set (adds the key plus a `Double` timestamp) and every
   `status` the longest rawValue (`"revokePending"`, 13 chars). ³ Genuinely constant at every count
   0–255 and every status/timestamp combination — that's the entire point being measured.

   **Cross-container forensic concern, found 2026-09-05: don't let this container's *own* efficient
   size become a fingerprint.** 10,789 bytes is cheap relative to the contact `LayerStore`'s existing
   32 KB per slot, but if this container settles on its own tighter number, an examiner who knows both
   values can identify "this file is the BEK+entries container" purely from its distinct size, same
   problem as trustee count leaking via length, one level up. Reusing `LayerStore`'s existing 32 KB
   constant here instead — rather than the cheaper 10,789 — costs roughly 22 KB × 32 slots ≈ 700 KB of
   otherwise-unneeded padding, trivial on-device, in exchange for making this container and the contact
   blob byte-identical in size. Not yet decided whether to take the cheap number or the matching one;
   leaning matching, given the cost is negligible and the alternative reopens the fingerprinting
   question item 5 below also raises for directory structure.

   **Two open sizing questions are now blocking each other, found 2026-09-06.** This item's own number
   (10,789 vs. 32 KB) is still "leaning," not closed. `RECOVERY_BUFFER_LAYERING.md`'s own container size
   (its item 5, backup-contents cap) is fully open with no number at all. But this doc's item 5
   (file-identity) requires *every* file in the shared pool to be the same size for its whole argument
   to hold — so neither container's size can actually be finalized independently, and nobody has yet
   checked whether the recovery-buffer container's real content (potentially a full pending backup
   snapshot) even fits under whatever this container settles on. Resolve both together, not in
   isolation — closing this item alone doesn't verify item 5's premise, it just asserts it.

   **`formatVersion` — folds the padding rule into the byte a decoder already needs to trust**, rather
   than inventing a separate cap-version concept. `formatVersion = 1` means "capacity is sized to the
   255 ceiling, write policy is 10"; a future change to either bumps it. Absence of the field entirely
   (not `0` — genuinely absent) marks the legacy, pre-slotting device-wide row, which predates the whole
   concept and is distinguishable from it on that basis alone.

   **Not yet implemented.** A first pass shipped `prepareBEKShards`'s guard and matching UI enforcement
   without this wire-format work or the storage-capacity question behind it — reverted (`2b49457`) once
   the gap surfaced. Nothing about the numbers or wire format above is code yet.

4. **Convention or cryptography for the BEK field's slot separation** (Bug 92) — splits into two
   applications with different blockers and costs. **Both halves now decided, separately, on different
   dates: live-slot 2026-09-05 (build it), exported-file 2026-09-06 (ship opt-in, 6-word passphrase).**
   Neither implemented yet.

   **Why not a slow KDF.** `PIN+Manager.swift`'s existing verifier derivation is
   `HKDF(seKey, info: label ∥ pin)` — deliberately fast. `plan.md` records PBKDF2 being tried for this
   exact purpose and removed: *"on-device code execution defeats any KDF regardless of iteration
   count... SE key prevents all off-device attacks"* doing the actual work instead. Binding derivation
   to the SE key removes the offline-brute-force attacker entirely; the same shipped pattern fits here
   too, not a new primitive.

   **The live slot — decided, build it.** Same fold-PIN-into-`info` convention the verifier already
   uses, applied to the slot key instead of a verifier: `slotKey(depth) = HKDF(inputKeyMaterial:
   vaultKey, info: "bek-slot" ∥ depth ∥ pin(depth))`. A session at depth 2 holds the vault key (from
   biometric auth, not depth-specific) and depth 2's own PIN (from the PIN entry that reached it) — it
   never holds depth 0's PIN, so it cannot compute depth 0's `slotKey` even though it holds the same
   vault key depth 0 would use. This closes §4's vault-key-extraction risk: the boundary between depths
   stops being "the app's code chooses not to read the other slot" and becomes "the key material to
   read it doesn't exist in this session." Touches only local storage — doesn't touch Shamir
   reconstruction (which splits raw `bekBytes`, independent of how any one device seals them locally)
   or restore UX on a fresh device (which derives its own `slotKey` under its own new PIN). No
   identified downside; scope is a key-derivation change only, not a new field or format.

   **Not yet implemented.** Decided, not built — same status as item 3 until this branch's actual
   implementation work starts.

   **The exported `.occbak` file (Bug 92's original proposal) — decided 2026-09-06: ship as an
   opt-in, 6-word passphrase, not a PIN.** Revises the original `slowKDF(PIN, ...)` proposal on two
   points worked through in design:

   **Passphrase, not PIN — and reuses existing infrastructure.** `Manager.PassphraseGenerator`
   (`Passphrase+Manager.swift`) already exists, already shipped for the UWB pairing ceremony's Diceware
   confirmation — EFF large wordlist (7776 words), `SecRandomCopyBytes`-backed generation, no new
   dependency. At 6 words (log2(7776) × 6 ≈ 77.5 bits, vs. a 6-digit PIN's ≈ 19.9), this is comfortably
   past feasible even for dedicated state-actor-scale offline brute force — rough estimate, generous
   assumptions, ~60 years at 10¹³–10¹⁴ guesses/second, versus low single-digit days for 5 words. 6
   chosen deliberately over the function's own 5-word default for that margin. **A fresh passphrase
   generated per export, not the app's own unlock PIN** — shown once at export time, the user saves it
   themselves. This also removes the original proposal's "PIN rotation orphans old exports" cost
   entirely: it's independent of the app PIN, so rotating that PIN never touches a past export.
   Sufficient entropy also removes the slow-KDF question from before — plain `HKDF`, the same pattern
   used everywhere else in this design, is enough once the input itself carries 77.5 bits.

   **What this actually protects, stated precisely rather than implied more broadly — the scope
   decision that makes shipping it defensible.** Entropy defends against an adversary who obtains the
   exported file *without* the owner's cooperation — found in `Documents/Inbox` (Bug 101), intercepted
   from a device backup, or a subset of trustees compromised independently. It defends nothing against
   a coercer who has the owner detained: a human-memorizable secret can be compelled from the one
   person allowed to know it, same reason duress PINs exist elsewhere in this app. Sharper than a gap —
   this reintroduces a single point of coercion Shamir's own design eliminates (no party, including a
   coerced owner, can reconstruct alone; recovery needs `threshold` *independent* trustees). Before this
   feature, a coercer holding the owner and the file still needs to separately reach several trustees.
   After, if they can also compel the passphrase, they don't. **Accepted, not fixed** — a duress
   variant (a second passphrase opening a decoy/empty result, mirroring duress PINs) was considered and
   explicitly not built here; real design work on its own, out of scope for this decision. Document the
   boundary plainly wherever this ships in-app: protects opportunistic and third-party exposure, not a
   detained-owner scenario.

   **Word selection: auto-generate by default; at most one word swappable via search.** Full free
   choice for every word was considered and rejected — human-chosen "memorable" words are well-
   documented to cluster far from uniform, materially cutting the effective entropy this whole decision
   rests on. Bounding a swap to one word caps the cost at that one word's ~13 bits rather than losing
   most of the passphrase's strength to predictability.

   **Two implementation constraints, found 2026-09-06 during review — both are precedent, not new
   ground.** Neither is optional if this ships:
   - **The word-search field needs `.autocorrectionDisabled()` and `.textInputAutocapitalization(.never)`.**
     Without them, a searched-but-not-chosen word still lands in the system keyboard's dynamic-text
     dictionary — outside this app's storage, outside its threat model, permanently — exactly F1's
     finding (`Docs/Audit/OPEN_LIMITATIONS.md`) for vault entry content, applied to a new field that
     didn't exist when F1 was fixed.
   - **Any "copy passphrase" convenience must go through `UIPasteboard.copySensitive`, never
     `UIPasteboard.general.string =` directly.** F2's exact fix — `.localOnly` plus a 120s expiry —
     exists because one call site got the bare setter wrong once already; this is a new call site for
     the identical class of secret.

   **Minor, pre-existing, non-blocking:** `generate()`'s `randomValue % 7776` carries the same shape of
   modular bias already tracked and rated negligible elsewhere in this codebase (Bug 72, ~3.7×10⁻⁹) —
   different function, same class of issue, worth a one-line note if touched, not a blocker here.

   **Not yet implemented.** Decided, not built. This half touches `RECOVERY_BUFFER_LAYERING.md`'s
   territory (the exported/pending backup contents), not this container.

5. **File-identity architecture — settled 2026-09-06: one shared pool, generalized beyond the original
   framing.** §5's "Where it lives" traced the existing contact-blob backend
   (`AppGroupLayerStoreBackend.swift`) and found it already avoids magic bytes and fixed filenames, but
   still uses a purpose-named dedicated directory (`"blobs"`) — a residual signal once a second and
   third differently-purposed container exist alongside it: an examiner who's read this app's source
   learns "a concealment subsystem lives here" from directory structure alone, before touching a byte,
   and with multiple purpose-named directories, learns roughly how many subsystems exist. Worse than a
   passive gap — it lets a coercer target compulsion precisely ("this exact file is your recovery-key
   container, give us that key specifically") instead of only being able to demand a key for an
   undifferentiated pile of look-alike files.

   **Decision: one shared, undifferentiated pool for every internal concealment container** — same
   naming/renaming-on-every-write/size convention, disambiguated purely by which of the app's own keys
   successfully opens a given file (`AES.GCM.open`'s own authentication failure standing in for a magic
   byte, for free; no new primitive needed). Cost is a handful of trial decryptions per lookup —
   trivial for a fixed, small key set.

   **Generalized further than the original A/B framing: one pool, not split by key domain.** No
   security reason to keep biometric (vault key) and non-biometric (Secure-Mode, recovery-buffer)
   containers in separate pools — protection comes entirely from the key, not the filesystem location,
   and splitting by domain would just reintroduce a smaller version of the same signal this decision
   removes. Fewer distinguishable groupings is strictly better.

   **The existing, already-shipped contact blob migrates into the pool too**, not just the two new
   containers — the one real cost beyond what was originally scoped. A one-time migration step
   alongside Stage 1's other migration work: move the blob out of its current dedicated `"blobs"`
   directory into the shared pool under the new naming convention. No special tombstoning needed for
   the vacated directory — consistent with the earlier finding that app-update filesystem changes
   aren't something this project's threat model defends against (no assumed before/after snapshot
   comparison capability).

   **Exported `.occbak` files stay out of the pool, deliberately.** These are a different kind of
   object — user-visible, meant to leave the device via a document picker — not hidden, device-resident
   state. Folding them in would blur a distinction that's load-bearing: `B4`'s strategy depends on an
   internal blob being indistinguishable *from* an ordinary export, which requires them to remain
   separate artifacts that happen to look similar, not the same storage.

   **Dependency, not a blocker on this decision:** `RECOVERY_BUFFER_LAYERING.md`'s own "where it lives"
   needs to adopt this same pool for the property to close completely — a container left in its own
   separate directory while everything else shares a pool just relocates the signal. Not yet applied
   there; picks up whenever that document's storage section is next touched.

   **Not yet implemented.** Decided, not built.

6. **Item 4's live-slot fix does not cover vault entries — found 2026-09-06, decided 2026-09-06.** §4
   describes the threat as a coercer with the vault key decrypting *every slot*, "including
   `shardMetadata` — trustee counts and identities." Item 4's remedy is titled and scoped to "the BEK
   field's slot separation," and its `slotKey(depth)` formula is applied only to the BEK record. But
   §5.1's target design has **two** separately-sealed fields per slot — the BEK record and sensitive
   vault entries — and the same vault key opens both. Once S8 is built, a coercer holding the vault key
   can still decrypt every other depth's vault entries — seed phrases, key tokens, notes, the most
   sensitive content in the app — by the identical mechanism item 4 was supposed to close. The fix
   landed on the less sensitive of the two fields sharing the container.

   **Resolution: the identical mechanism, own domain-separated key.**
   `entriesSlotKey(depth) = HKDF(inputKeyMaterial: vaultKey, info: "vault-entries-slot" ∥ depth ∥
   pin(depth))` — same shape as item 4's `slotKey`, different `info` string. Not a shortcut: two
   separately-sealed fields get two separately-derived keys, the same domain-separation discipline
   already used elsewhere (`K3`: distinct `info` strings for the blob key and PIN verifier keys
   specifically so a compromise of one says nothing about the other). One shared key protecting both
   fields would fail that standard.

   **The frequency question this raises that item 4 didn't have to answer.** The BEK record is read
   rarely — setup, distribute, export, restore. Vault entries are read constantly — every Vault tab
   open, every entry displayed. Deriving from the raw PIN on every read would either force re-deriving
   from PIN each time or force retaining the raw PIN in memory for the session, itself a new exposure.
   Resolution: derive `entriesSlotKey` once, at the moment the depth's own PIN is verified to reach
   that depth, and cache the *derived key* — never the raw PIN — for the scene-phase duration, cleared
   on background. Identical shape to **C2**'s existing cache for the hybrid local DB key
   (`Manager.Key`), not a new caching concept. Architecturally sound because reaching any depth already
   requires that depth's PIN entry first — there is no path to vault entries that skips it, so the PIN
   is always available at the exact moment this derivation needs it.

   **Not yet implemented.** Decided, not built. Blocks nothing today — S8 isn't built yet — but must
   ship alongside it, not be discovered as a gap after.

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

## 10. Known bugs — this container's

Scoped view into `Docs/Features/Secure Mode/bugs.md`; that file stays canonical for full reasoning.
`RECOVERY_BUFFER_LAYERING.md` §7 carries its own container's bugs — not repeated here.

| Bug | What | Status |
|---|---|---|
| 92 | A backup file is readable from any layer (offline half) | open — complementary to this design, see §4 and §8 item 4 |
| 102 | The BEK has no layer concept | **this document** |
| 105 | A duress layer can distribute shares of the real BEK | open — §6; closes via Stage 1+2 |
| 88 | Backup ignored `visibleThroughDepth` in both directions | fixed — export/import are depth-scoped |
| 94a | Remedy 2's attestation field unpadded | fixed — every op ships an attestation, real or filler |

Adjacent, not this container's subject, same root cause: Bugs 103/104 (inbound views render a hidden
contact's identity) — closed as duplicates of an accepted limitation, but instances of "the depth
dimension was not applied at the view layer."

---

## 11. Tripwire

`VaultEntryType` has `document` and `photo` **commented out**. The whole fixed-slot design, in both
containers, rests on a vault backup being kilobytes. Enabling either makes the vault bulk data and
invalidates this container's design entirely. That enum is the place to notice, so the constraint
belongs as a comment there too.

---

## See also

[`RECOVERY_BUFFER_LAYERING.md`](RECOVERY_BUFFER_LAYERING.md) — the shard buffer, restore/arming state,
and `CustodyShard`. Independent of this document except at §7 Stage 5 (completion) and §9's
`storePendingRestore` soft spot, both noted at their point of contact above.

[`VAULT_BACKUP_GUIDE.md`](VAULT_BACKUP_GUIDE.md), [`VAULT_SSS_GUIDE.md`](VAULT_SSS_GUIDE.md) — the
spec docs for the behavior this design replaces. Both describe today's device-wide BEK/shard machinery
as shipped; this document is why and how that changes, not a second description of what it does. Keep
their own "Secure Mode" closing sections pointed here as this design's decisions land.

# At-Rest Layering — Decision Framing

**Status:** framing only, no decision taken. **Compiled:** 2026-09-02.
**Owner entries:** `forensic-trace-avoidance.md` S5 (contacts) and S8 (vault entries) — the two
accepted gaps this decision would close or knowingly re-accept.
**Downstream:** `Occulta/Features/Vault/BEK_LAYERING_REFACTOR.md` §2.1, §2.2, and open decision §4.2.

**What this is.** Secure Mode layers *classification* nearly everywhere and *storage* almost nowhere.
S5 and S8 are the same gap in two model types; the BEK refactor is about to design a third instance
of the same fixed-slot pattern for a fourth consumer. This frames them as one decision, and records
what already ships so the answer is derived rather than invented — the BEK slot cap (§4.2 there) has
no anchor precisely because it was being picked before this question was settled.

---

## 1. The shared gap

| Item | What is layered | What is not | Status |
|---|---|---|---|
| S5 — sensitive contacts | `visibleThroughDepth`; the UI filter | the rows themselves stay readable under the canonical DB key, derivable on an unlocked device | accepted, "Phase 1" |
| S8 — vault entries | `visibleThroughDepth` (exact-match), stamped at activation Step 8 | `id` and `createdAt` are plaintext columns; row count is identical at every depth | accepted, Medium |

Both have one shape: **the classification is per-depth, the storage is device-wide.** It is the same
observation `BEK_LAYERING_REFACTOR.md` §1 makes about recovery — "device-wide in an app that is
layered everywhere else" — applied one level down, to the data recovery exists to protect.

That matters for sequencing. Per-layer recovery built on a store that is not itself layered inherits
the gap it is trying to close.

## 2. What already exists — and it is most of the mechanism

`LayerStore` (`SecureMode+LayerStore.swift`, `LayerStore.md`) is already a per-depth fixed-width
container, shipped:

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

That last point is the answer to "we should not impose caps, we need graceful flexibility." A fixed
envelope is not negotiable — it is what makes an occupied slot indistinguishable from an empty one
(§3 of the BEK doc's reasoning, and B3/B6 here). What *is* negotiable is whether the user can see the
budget. This codebase already chose "yes" for contacts, and that pattern is the one to copy rather
than inventing a per-entry byte cap discovered at export.

## 3. The constraint that shapes every option: two protection domains

`LayerStore.md` excludes vault per-entry keys deliberately, and the reasoning generalises to vault
content as a whole:

> Storing them would widen the attack surface since a store compromise requires only the SE Secure
> Mode key, bypassing the biometric gate that otherwise protects vault content (Bug 8).

The blob key is `HKDF(seKey_secureMode, info: "blob-key")` — no biometric gate. Vault content sits
under a separate SE key requiring a fresh biometric evaluation. **Putting vault entries into the
existing store collapses those domains and strictly downgrades vault protection.** It is also why S8
is rated below S5: a duress-PIN-only coercer cannot open the vault at all, so the row-count tell needs
duress PIN *and* forced biometrics to be reachable.

**Consequence for the plan:** "use one mechanism for vault, BEK and import" holds — but as *one
mechanism, separate instances under separate keys*, not one container. Shared: slot geometry, fixed
plaintext size, eager creation, full-regeneration-on-write, capacity estimation and its UI. Not
shared: the key, the file, or the lifecycle.

## 4. Candidates

**Contacts (S5).** Design B is already specified and deferred: sensitive contacts become unreadable
shells in the DB, the blob is the sole readable copy, loaded into memory on normal unlock and wiped on
lock. `LayerStore.md` notes the infrastructure already supports it; the named work is four steps.

**Vault entries (S8).** Three, from that entry plus this framing:
1. Leave as-is; re-accept the gap explicitly, on the elevated-attacker argument.
2. Decoy row padding — S8 calls this "complexity without a strong attacker model."
3. A second `LayerStore` instance keyed under the vault's biometric-gated SE key, holding sensitive
   entries as the canonical copy. Preserves §3's separation; reuses the shipped mechanism.

**BEK and backup contents.** Consumers of whichever shape wins, rather than the new sibling file
`BEK_LAYERING_REFACTOR.md` §2.2 proposes. That proposal predates this framing and did not weigh
`LayerStore` as the host — worth re-deciding, noting §2.2's own objection (bulk content must stay out
of `AppLayerConfig`, since SwiftData loads the whole row on every `requireConfig()`) applies to that
row, not to a `LayerStore`-shaped file.

`CustodyShard` is a fourth consumer already waiting: `LayerStore.md` records its duress-mode
accessibility as an explicitly deferred decision, and BEK §2.3–§2.4 needs the same answer.

## 5. Open questions

1. **Does the vault get storage layering at all**, or is S8 re-accepted? Everything else follows.
2. **If yes — one shared instance under the vault SE key, or per-consumer instances?** More instances
   means more fixed-size files to justify; each is eagerly created and permanently present.
3. **What is the vault slot budget?** 32 KB holds ~30 contacts with ML-KEM material; vault entries are
   far smaller, so the same 32 KB is a generous starting point — but it must be picked against the
   §6.5 tripwire (`VaultEntryType.document`/`.photo` stay commented out, or this design breaks).
4. **Does the BEK move into this mechanism**, superseding §2.2's sibling file?
5. **Sequencing against Bug 105**, which is live on shipped code and was the reason the BEK work was
   compressed into a patch release. If the BEK refactor now waits behind this, 105 needs a deliberate
   interim answer — accept it documented, or take the remedy the BEK doc dislikes (refusing
   distribution above depth 0, which buys a new depth-conditional tell).

## 6. What this does not change

The §6.5 tripwire becomes *more* load-bearing, not less. Today `VaultEntryType`'s commented-out
`document` and `photo` cases constrain a backup format that does not exist yet. Under any option 3
here they constrain the live store as well — which is an improvement: one constraint, enforced where
it breaks loudly, instead of an assumption two separate designs quietly depend on.

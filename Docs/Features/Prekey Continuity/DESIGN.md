# Prekey Continuity — Design

**Status:** Proposed 2026-10-06; every decision taken except D7, deferred. Stage 0 merged (PR #87); stages 1 and 2
(PRs #94, #97) and Bug 165's fix (PR #100) merged 2026-10-13 into `v2.0.0/prekey-refactor`, not yet in the release
branch; stages 3 and 4 (PRs #108, #109) merged 2026-10-15 into it. The refactor is complete; it ships in 2.0.0,
merged into the release branch before the version number reaches 2.0.0. **Target: v2.0.0** (D8). **Grace period: 30 days** (D1). **Compose indicator: a third state and
per-state descriptions** (D2). **Prekeys as Enclave blobs in the sealed record** (D9). **Batches of
15, refill at 5** (D4). **Identity challenges in group format** (D3, 2026-10-07). **Replay guards** (D5, 2026-10-07).
**Downgrades ruled out by release order** (D6, 2026-10-07). **Seeding at the exchange (§3.2,
stage 5, step 6) deferred out of v2.0.0** (2026-10-07), which leaves D7 moot until it returns.
Every point that needs a decision is listed in §10 and marked where it comes up. §9 records research that
challenges where prekeys are stored at all.

**Related:**
- `Docs/Features/Crypto/bundle.md` — what the bundle modes are. This document changes when each mode is used.
- `Docs/Features/Bundle/SPEC.md` — the v4 wire format. §3.1 and §3.3 add two optional fields to
  `PrekeySyncBatch`.
- `Docs/v2.0.0/HARDENING_STEPS.md` — step 6 (prekeys in the exchange) is §3.2 here. Step 17 (random prekey
  tags, per-contact secret, Enclave padding) changes the same storage, so the two are designed together (§6).
- `Occulta/Features/SecureMode/PASSPHRASE_LAYER_KEYS.md` §2 — "message keys must not route around the layer
  keys". Everything here keeps to it.
- `Docs/Features/Secure Mode/bugs.md` Bugs 155–160 — the review this design came out of. §3 fixes 155, 156,
  157 and 158 as part of the design.
- `Docs/Features/Occulta for Organizations/DESIGN.md` — one-way delivery from an organization to its clients.
  Depends on §3.1, and on §3.2 (stage 5) being brought back.

Code references are against `7affd76`.

---

## 1. Problem

A message to a contact gets forward secrecy only if we hold one of their one-time prekeys. They can only give
us more by sending us something. So we fall back to the **long-term** mode (`.longTermFallback` /
`.longTermNoPQ`), which derives the key from the two identity keys:

1. **The first message in each direction.** The in-person exchange carries no prekeys.
2. **After 15 messages without a reply.** `PrekeySecretsManager.defaultBatchSize` is 15. A new batch is generated
   only when a long-term bundle arrives, and travels only on the recipient's next message. In a two-way
   conversation that is about 1 in 16 of each side's messages; in a one-way burst, every message past the 15th.
3. **Every identity challenge and response.** They are sealed long-term on purpose
   (`IdentityChallenge.Manager.sealIdentityBundle`).

A long-term bundle is worse than "no forward secrecy" suggests. ECDH is symmetric, so **either** phone can
derive its key, and the identity keys never change, so it stays openable **for as long as either phone
exists**. Under the v2.0.0 threat model the adversary keeps every `.occ` file, so each long-term bundle is a
standing liability on two devices.

## 2. Goals and non-goals

**Goals**
- No message between two contacts on a current build uses the identity keys for its session key once the
  contact has replied for the first time. Before that first reply, with §3.2 deferred, messages to a new
  contact use the long-term key, and the compose indicator says so (§7). **Open, not accepted.**
- A message sent while the sender is out of one-time prekeys is exposed on the recipient's device only, and
  only until the recipient's next batch replaces the key (§3.1, "Without a reply").
- Nothing new is visible to someone holding the files, the keychain, or a coerced unlock.

**Non-goals**
- **Contacts on older builds.** They can't take part; long-term stays their path (§5).
- **Post-compromise security** (a Double Ratchet). Rejected in §4.2.

---

## 3. Design

Four parts. §3.1 is the one that removes the long-term mode; §3.2 and §3.3 make one-time prekeys the normal
case so §3.1 is rarely used; §3.4 keeps identity challenges from standing out once long-term bundles are rare.
§3.2 is deferred out of v2.0.0 (2026-10-07); the other three ship.

### 3.1 Last-resort prekey

Each batch carries one extra prekey that may be used more than once. When the sender runs out of one-time
prekeys, it seals to the last-resort key instead of the identity keys.

**Generation (recipient, B).** Generated with the batch: one more CryptoKit Enclave key, with the same access
control, held in the record as a blob like the one-time keys (D9), with its public key derived from the blob
when the batch is sent. The batch records which of its keys is the last-resort one.

**Wire.** `PrekeySyncBatch` gains one optional field, inside the sealed payload:

```
lastResort: WirePrekey { id, publicKey }   // the same type as the one-time keys; absent from older builds
```

Synthesized `Codable` omits a nil optional and ignores an unknown key, so older builds decode a batch that
carries it, and batches without it encode exactly as today; the existing interop vectors don't change. New
vectors cover a batch that carries it.

**Sending (A).** On accepting a batch, A stores its `lastResort` in the contact's record, replacing the
previous one, and keeps it when the one-time keys run out. When `takeInboundPrekey` finds none left and a
last-resort key is stored, A seals in the normal forward-secret mode with a fresh ephemeral key, as for a
one-time prekey, with two differences:

- the key is **not** removed after use;
- the cleartext `prekeyID` is not the key's ID. It is `HMAC-SHA256(lastResortID, ephemeralPublicKey)`,
  truncated to 16 bytes, with the UUID version-4 and variant bits set, formatted as `UUID().uuidString` formats
  one. The HMAC key is the last-resort key's own ID as raw bytes.

A fixed ID would appear in the clear on every bundle sealed to that key and link them all. The ephemeral public
key is new for every message and already in the bundle, so it serves as the nonce; the derived ID changes with
it, can't be computed without the last-resort key's ID, and has the same format as a real one. Mode, sizes and
the sender's ephemeral signature are those of a one-time forward-secret bundle, so the two can't be told apart
on the wire.

**The last-resort key's ID is its secret (decided 2026-10-11).** It has 122 random bits, travels only inside
the sealed batch, and unlike a one-time key's ID is never written in a bundle's `prekeyID`: only the derived
value is. So it can key the HMAC, and a separate 32-byte `idKey`, the first design, was dropped from the wire
and both records. The condition is that the real ID never appears in the clear; a test checks that a
last-resort bundle's `prekeyID` never equals it and differs on every send.

Used only when the bundle goes out in group format (`targetVersion.supportsGroups`), so the
`senderEphemeralSignature` authenticates it. A contact who sends a last-resort key is on a new build, so this
always holds unless their recorded version is stranded; in that case A falls back to long-term, as today.

**Receiving (B).** In `deriveInboundKey`'s forward-secret branch, when no stored one-time prekey matches the
`prekeyID`, B computes the derived ID for each last-resort key it still holds for this sender and uses the one
that matches; none matching rejects the bundle with the generic error, like any other unknown ID. The
candidates are one per batch still in the record: the pending one, the delivered one, and retired ones within
their grace period. That is one HMAC per candidate and no Enclave operation; a 32-slot group bundle against the
largest record is about a thousand HMACs. The last-resort key is **not** consumed. `findAndOpenRecipientSlot`
consumes whatever key opened the slot (its `defer`), so it needs to know which kind of key it used.

**Bookkeeping on receipt.** A last-resort bundle means "the sender is out of one-time prekeys". It replaces
today's long-term trigger:

| State when it arrives | Meaning | Action |
|---|---|---|
| No pending batch | Sender used up everything we gave them | Generate a batch (with a new last-resort key) |
| Pending batch, and the key is that batch's last-resort key | Sender received the pending batch and has used it all | Clear it, generate a new one |
| Pending batch, and the key is older | Sender hasn't received the pending batch yet | Nothing; it keeps riding |

The same "is the used key in the pending batch" test also decides one-time receipts, which is Bug 157's fix.

**Retirement and deletion.** One rule covers one-time and last-resort keys, and it is Bug 156's fix:

> Batch *n* is **retired** when a key from any newer batch is first used. Its remaining keys, the last-resort
> key included, are **deleted** after a grace period.

That the first use of a newer batch proves the sender has finished with batch *n* depends on the sender
using its prekeys oldest first, which §3.3 makes a rule. It also holds for older builds, which replace their
store rather than append to it.

**What the leftover keys are.** Because the sender uses batch *n* up before touching *n + 1*, every key of
batch *n* still in our Enclave at retirement was used to seal a message we haven't opened: one still in
transit or opened out of order, one lost, or one the sender made and never shared. They are not spare keys.
The exception is a sender on an older build, which drops up to `T` unused keys when it replaces its store.
So the grace period is how long we keep the ability to open a message we know was sent. Shorter loses late
messages, which never happens today; longer leaves them openable by whoever later holds the phone and the
file (Bug 156).

**Grace period: 30 days from retirement (D1, decided 2026-10-06).** By time, not by message count. A count
leaves a contact who goes quiet holding old keys indefinitely, and their unopened files are where the risk
is. 30 days is a judgement: how long users leave `.occ` files unopened is not measured, as for Bug 82a.
Retirement time is stored per batch in the contact's record. Consequences that come with the rule:
- **A file opened more than 30 days after its batch retired can't be opened.** It fails with the same generic
  error as any other unopenable file, not a distinct one.
- **Deletion can come later than 30 days.** The sweep needs the contact's record, which after step 17 opens
  only at a depth that sees the contact. A hidden contact's retired keys are deleted at the first such session
  after the 30 days, together. That burst is step 17's open "repeated images" item, not a new kind of change.
- **The clock is the recipient's.** Moving it forward deletes early, which loses messages and exposes
  nothing; moving it back keeps keys longer, which needs the unlocked phone.
- **Deleting at retirement, with no grace, was rejected (2026-10-11).** The contact uses keys oldest first (since
  stage 4 a new batch is appended after the old one's keys rather than replacing them), so once they use the new
  one, nothing new can be sealed to the old keys: deleting them at once would never delete a key the contact holds. But a file sealed to an old key just before the switch and
  opened after a newer one would be lost, with the generic error. That is a message lost that was never lost in
  transit, so the grace stays. Deleting earlier keys of the batch still in use was rejected for the same reason,
  and more strongly: it loses any two files opened out of order, not only those either side of a batch change.

**No key is marked expired (recorded 2026-10-15).** Expiry is deletion: retirement is a date on our own batch, and
the sweep deletes the batch, last-resort key included, 30 days after it. The contact's side marks nothing and
can't, since it doesn't see our retirements; a timer there would be wrong anyway, expiring keys a contact who
hasn't replied in months may still validly use. What keeps a sender off an expired key is structural: we retire a
batch only when they first use a key from a newer one, and by then they hold none of the older batch's keys,
since they use keys oldest first, and their last-resort key switched to the newer batch's when they accepted it.
So every key a contact holds of ours is one we still hold, in a batch that hasn't retired; only a message already
in transit can reach a retired key, which is what the grace is for. `PrekeyConversationSimulationTests` checks that
after every step, through 40-day silences and sweeps; `PrekeyBookkeeperLastResortExpiryTests` and
`PrekeyConversationTests.retiredLastResortGrace` check that a retired last-resort key opens for 30 days and not
after. The one way around it, an older copy of the database put back, isn't open to a user: the store is excluded
from iCloud and Finder backups (Bug 70), and nothing restores prekey records.

**Without a reply.** A last-resort key retires only when the sender uses a key from a newer batch, and only
the recipient can send one. A recipient who never replies keeps the key, and every message sealed to it stays
openable on their phone, for as long as that lasts. There is no better fallback: capping the key's life
would push the sender back to the identity keys, which are exposed on both phones, forever. What the user
can do is wait for a reply before sending something sensitive, which is what D2's indicator is for.

**Replay (D5, decided 2026-10-07).** A last-resort bundle opens again whenever it is delivered again, until
its key is deleted, and is processed again each time. A long-term bundle already behaves this way, forever.
That was harmless because long-term bundles are barred from anything with lasting effect. A last-resort
bundle uses the forward-secret mode, though, and the receive path accepts backup-piece operations on
forward-secret slots, which was safe only because one-time keys made each such bundle single-use.

What a repeat delivery would do:

| Effect | On repeat |
|---|---|
| Message shown again | Yes. This is what D2's "Multiple Views" already says |
| Identity challenge | Nothing: each nonce is single-use, and challenges go stale |
| Prekey batch inside it | Nothing, once Bug 158's batch IDs drop a batch already seen |
| "Sender is out of keys" signal | At most one unneeded batch when none is pending |
| `.replace` (trustee) | Stores another copy of the piece each time: unlike `.distribute`, it doesn't check for one already held |
| Old `.distribute` / `.replace` after a newer one (trustee) | **Brings back a piece the owner replaced**, undoing a rotation. With `newKey`, that rotation exists to revoke a dropped trustee's piece (Bugs 141, 144) |
| Custody manifest (owner) | Can flip a piece's status from a stale report |

**Decided: (a), with two guards on the trustee side and a test matrix.** *Revised 2026-10-12: G2′ and the matrix
are replaced by Bug 163's lineage, deferred; see "Revised 2026-10-12" below.*
- **Backup-piece operations and custody manifests ride only on one-time keys.** The sender doesn't attach them
  when it seals to the last-resort key. The receiver drops them from a slot opened with a last-resort key,
  as it already does on long-term slots. A trustee on the last-resort key confirms later, as on long-term
  today, which refilling makes rare. *Built 2026-10-12. The receiver's drop didn't reach a one-to-one bundle,
  which carries them in the shared payload (`bugs.md` Bug 164); it does now, on long-term and last-resort
  slots alike.*
- **Only the current last-resort key signals "out of keys".** A repeat delivery sealed to an older one
  generates nothing.
- **G1: `.replace` skips a piece it already holds,** as `.distribute` does (protocol case 15). This stops
  duplicate rows. *Built 2026-10-12.*
- **G2′: each custody row carries a "supersedes" field,** the ID the piece replaced, taken from the
  `.replace` that installed it. While the row is held, an operation carrying that ID is rejected, which
  blocks the most damaging replay: undoing the latest rotation. The field is inside the existing sealed row,
  always present, and always the same size (a random ID after a plain `.distribute`). It is written in the
  same write as the piece and deleted with it, so it adds no record, history or write that the row doesn't
  already have. It remembers one generation back. Older replays rely on the first bullet.
- **The replay matrix is the main safety net.** Every case in `Occulta/Features/Vault/SHARD_PROTOCOL_CASES.md`
  is run with each operation delivered twice and in every order. Custody state must match a single in-order
  delivery.

**Revised 2026-10-12: G2′ and the matrix are dropped; ordering is Bug 163's, deferred.** Working out the matrix
showed that no rule on the trustee's side can make custody match in-order delivery, replay or not. A `.replace`
names only the piece it replaces, a re-split drops the previous split's unsent operations, and the trustee can't
tell which pieces belong together. So one lost or late `.replace` leaves a stale piece behind, and ordinary
out-of-order delivery of one-time-key bundles already does that today (`bugs.md` Bug 163, present in v1.11.1).
What was tried, each failing for that reason:
- **G2′**, one superseded ID per row: covers one generation; two re-splits arriving in reverse still leave the
  first piece.
- **A chain of the last N superseded IDs:** fails at N + 1.
- **Applying only the newest bundle's operations**, ordered by which of the receiver's one-time keys each bundle
  used (a "newest used key" position kept in the prekey record): stops an older piece coming back after a newer
  one, but drops a late `.replace` that was the only thing that would remove its predecessor.
- **Letting a late bundle only remove, never add:** converges when nothing is lost, but not when a bundle is.

The fix that works is a lineage per owner depth and trustee, so the trustee holds one piece per lineage and the
newest replaces the rest. It is worked out in Bug 163 and deferred, with Bug 162's container, which would close
both. **What stands for replay:** piece operations and manifests never ride a last-resort slot, on either side, so a
redelivered last-resort bundle carries nothing to replay; and one-time-key bundles can't be replayed, since their
key is gone once used. The matrix's promise, every order matching in-order delivery, waits for Bug 163.

**Considered and rejected:**
- **A replay cache of opened last-resort bundles.** It is a stored list that grows with traffic from a
  contact. It would make "Multiple Views" untrue for the recipient's own reopening, and it would only add
  blocking re-display, which long-term messages never had.
- **G2, a per-owner list of retired piece IDs.** It would be a new per-owner record that outlives the piece,
  grows with every rotation, and changes on writes only that owner causes. For a hidden owner, that is
  another artifact with history.
- **Rejecting a piece older (by its signed `createdAt`) than one already held.** There is nothing safe to
  compare it with. A trustee legitimately holds several live pieces from one owner, one per depth
  (`VAULT_KEY_LAYERING.md`), so comparing per owner would judge one depth's piece by another's: a wrong
  rejection, and coupling between depths. And every re-split mints a new `entryID` (`prepareShards`,
  Bug 124), so comparing per `entryID` never compares anything. Making it work needs a signed lineage ID
  that survives re-splits. That is a wire change, and it would let a trustee link an owner's pieces into
  lineages and count how many of the owner's depths have backups.
- **M1, a counter in custody manifests.** It is a wire change, and the first bullet already makes manifests
  single-use.

### 3.2 Seed a batch at the in-person exchange

**Deferred out of v2.0.0, 2026-10-07.** With §3.1 and §3.3 in place, a pair leaves the long-term mode the moment
the contact first replies, since that reply carries their first batch. Seeding would then only protect what is
sent to a new contact before that first reply: usually one message, sometimes a short burst. Against that:
- a new exchange message and a version check, so exchanges with older builds still complete;
- D7's binding (below);
- end-to-end testing that needs two physical iPhones running the exchange, since UWB doesn't run in the
  Simulator, and every available phone holds real data.

What covers the gap meanwhile is D2's indicator. Before that first reply it reads "Multiple Views · Long-Term
Key — Hold back anything sensitive", so a user can send a short hello and wait. The remaining exposure, that
messages before a new contact's first reply use the long-term key, is **open, not accepted**. The section
below is kept as the design to return to.

**D7, as worked out before the deferral.** Bind the batch by sealing it under a key derived from the same
secret as the comparison words: the identity ECDH, the ML-KEM secrets and both nonces, under a separate HKDF
label. Send it right after the ML-KEM step and before the words appear, then hold it in memory and store it
only on Confirm. Matching words then prove the batch came from the person checked. Sealing also keeps the
last-resort key's ID, which keys its derived prekey IDs, confidential end to end, which signing alone would leave to the unauthenticated
session's encryption. If the batch hasn't arrived by Confirm, the contact is saved without it. Mixing the
batch into the words was rejected as fragile. Waiting for step 8 binds nothing unless step 8 adds session
certificates.

**Likely direction when this returns (owner's note, 2026-10-07).** Exchange the prekeys, or any other data the
pair needs at setup, **after** both users confirm the comparison words, authenticated with a key derived from
the confirmed secret. That key is symmetric, so it gives a MAC or AEAD rather than a signature; sealing with
AEAD also covers the confidentiality of the last-resort key's ID. Nothing is accepted until the human check has passed. What it
changes: today each phone's Confirm is local and tears its session down at once (`finish()` in
`KeyExchange.swift`). The session would have to stay up until both sides have confirmed and exchanged, and
the timeout and one-side-cancels cases would need defining. That replaces the send-before-the-words timing
above, whose only advantage is that a fast Confirm on one side can't cut the exchange short.

This is v2.0.0 step 6. It removes "the first message is always long-term". Additions to step 6's constraints:

- **The batch includes a last-resort key**, so the first burst of more than 15 messages is covered too.
- **It must be bound to the identity the user confirms.** The exchange runs over `MCSession` with
  `securityIdentity: nil`, so the session itself authenticates nothing; the diceware comparison does, until
  step 8. Someone in the middle who swaps only the prekeys could read the forward-secret messages sealed to
  them. So the batch is signed with the identity key, over a domain-separated payload
  (`"occulta-exchange-prekeys-v1"` ‖ both session nonces ‖ the batch), and is stored only after the
  exchange completes and the signature verifies against the identity key just received.
- **Its size doesn't depend on Secure Mode** (step 6's constraint). It is always 15 prekeys plus one
  last-resort key.
- **Keys need a home before the contact exists.** Prekeys are generated before the user saves the contact.
  With step 17b's random tags, they can be created untagged to any contact and recorded in the contact's
  record on save, and deleted if the user cancels. With today's `prekey.<contactID>.<uuid>` tags, the
  contact's identifier has to exist first. Check during implementation where `Contact.Profile` gets its
  identifier relative to the end of the exchange.
- **Older peers are unaffected.** The extra step runs only when both sides advertise it. How the exchange
  treats an unknown message today needs checking before choosing between a new message and a new optional
  field on an existing one.

### 3.3 Refill before running out; append instead of replace

A recipient knows how many of its one-time prekeys a contact still holds. It sends a new batch before they
run out, so a two-way conversation doesn't reach the last-resort key, as long as no more than `T + 1` messages go
one way between replies (below). **Built 2026-10-15 (stage 4).**

**Refill (B).** When the contact holds `≤ T` unused one-time keys from batches they have received, and no
batch is pending, B generates a batch, which rides its next message as any pending batch does.
**`T` = 5, with batches of 15 (D4, decided 2026-10-06, §4.1).** `PrekeyBookkeeper.needsRefill` decides, and
`ContactManager.replenish` calls it on receipt of a bundle sealed to a one-time key, after every check that can
reject it (Bug 159). `PrekeySecretsManager.replenishThreshold` and `needsReplenishment`, which counted keychain
items and had no caller, were removed.

The count comes from the per-batch records in the contact's record, not from `remainingCount(for:)`: the keys
left in our delivered batches that haven't retired, a key being removed as it's used. That function counts
keychain items by tag. It includes keys that will never be used (Bug 156), and it stops working once tags no
longer name the contact (step 17b). A key used for a message that never reached us still counts, so the refill
then comes later than it could, and the last-resort key covers the gap. Nothing is generated while a batch is
pending, so it makes one batch at a time, whoever triggers it.

**The limit on bursts (found building it, 2026-10-15).** A batch reaches the contact only with our next message.
At the start of a burst they may hold `T + 1` of our keys with no refill due, so a burst of up to `T + 1` = 6
always stays on one-time keys; a longer one may reach the last-resort key for the rest of the burst, never the
long-term key. `PrekeyConversationTests` and `PrekeyConversationSimulationTests` pin both.

**Append (A).** `PrekeyBookkeeper.accept` adds a new batch after the keys already held, instead of replacing
them, and `takeInboundPrekey` stays oldest first. That order is what makes the retirement rule in §3.1
work: by the time the contact starts our newer batch, they've used every key of the older one, so a retired
batch holds no unused key. At most two are kept (`maxInboundBatches`); a third, which shouldn't arrive, drops the
oldest. The contact's last-resort key becomes the newest batch's.

**Duplicates by ID, not date (Bug 158's fix).** Appending makes the duplicate check matter more: a late copy
of a batch already used would add keys B has already deleted, and messages sealed to them could never be
opened. `PrekeySyncBatch` gains an optional `id` (16 random bytes). A keeps the IDs of the batches it has
accepted, at most a handful, and drops a batch it has seen. A batch without an `id` comes from an older
build and keeps today's date rule. That keeps 158 open for older senders only.

**Only the last 8 IDs are kept, so a slot that opens again needs a date too (found in review of PR #110,
decided and built 2026-10-15).** A bundle on a slot that can be opened again, the long-term keys or a last-resort
key, can be replayed after its batch's ID has aged out of the 8, and would add a batch whose keys B has already
used up and deleted. So on such a slot a batch with a new ID must also be no older than the newest batch A has
accepted from that contact, by the sender's date: `latestInboundGeneratedAt`, updated for every accepted batch
and never lowered. On a slot sealed to one of A's one-time keys, which can't open twice, a new ID is enough.
`PrekeyBookkeeper.accept` takes `onReopenableSlot` for this; `ContactManager.acceptInboundBatch` sets it from the
key the bundle opened with. Guarded by `PrekeyBookkeeperReplayTests`, `PrekeyConversationSimulationTests.replayAfterIDsAgeOut`,
`PrekeyReplayWiringTests` (`openGroup` and `decryptSealed` pass the slot, no Enclave) and
`PrekeyConversationTests.replayedLongTermReply` (two phones, Enclave).

Open, needs a decision: a sender whose clock went back, while A is on their long-term or last-resort key, has a new
batch refused until one dated later than the newest arrives, so their clock must pass that date. That is Bug 158's
original behaviour, now only on a slot that opens again; on one of A's one-time keys their batch is taken.

### 3.4 Identity challenges

Once §3.1–3.3 are in, a long-term bundle between two current-build contacts is almost always an identity
challenge or response. Anyone holding the files would see that. It breaks a property the challenge was built
for: it is meant to look like an ordinary long-term message.

Moving challenges is not a sender-only change. `IdentityChallenge.Manager.openIdentityBundle` re-derives the
long-term key itself "as defense-in-depth" and opens the bundle with it. Every shipped build therefore
rejects a challenge sent any other way, including in group format, even though `OccultaApp` routes group
challenges to the handler.

**Decided 2026-10-07 (D3): option (a), challenges in group format to contacts at the new tier.** Option (b),
leaving them long-term, was rejected: once §3.1–3.3 are in, challenges would stand out to anyone holding the
files.

- **Sending.** A challenge and its response go through the same group-format path as a message, sealed with a
  one-time key, the temporary key, or, with neither, the long-term key. The last case keeps the header's rule
  that "identity verification must never fail because of prekey exhaustion".
- **Receiving.** Phase 2 (`decryptChallenge`) and phase 3 (`verifyResponse`) take the payload and sender that
  `openGroup` already opened and checked, instead of re-deriving the long-term key in `openIdentityBundle`.
  `openGroup`'s checks replace that defense-in-depth. The slot only opens with our own prekey or long-term key.
  For a forward-secret slot, `senderEphemeralSignature` is verified and, at this tier, required. And
  `senderProof` binds the routing fields, against outsiders only: in a bundle with several recipients each of
  them can compute it (Bug 165).
- **Authentication is unchanged in strength,** for a bundle with one recipient. The challenge was authenticated
  by long-term ECDH; it is now authenticated by an identity-key signature over the slot's ephemeral key. Both
  need the contact's identity private key. The response stays signed by the identity key after the contact
  approves it. With several recipients, a slot doesn't bind the body, so another recipient can rewrite it; see
  the review below.
- **Version gate.** Contacts below the tier keep today's long-term path, unchanged. The tier is
  `.bodyDigestCapable` (2.0.0, marker byte 0x09), added with Bug 165's fix and shared with it (decided
  2026-10-13), rather than waiting for step 17a's negotiation, which isn't built.
- **Bonus.** Challenge contents, including the typed context note, get forward secrecy instead of being
  openable from either phone indefinitely.
- **Bug 155.** New-tier challenges no longer look like an exhausted sender, so they stop triggering batches.
  Long-term challenges from contacts below the tier still would, so `decryptSealed` also skips batch generation
  when the payload carries `identityChallenge`. That needs Bug 159's reordering first, since generation runs
  before decoding today.

**Security review, 2026-10-12.** `openIdentityBundle`'s long-term reopening, which this section replaces, is
today the only check stopping a group member from forging a challenge: a slot doesn't bind the body it unlocks,
so a co-recipient can rewrite a group bundle's body behind the sender's genuine slot (Bug 165, confirmed by
`GroupBodyBindingTests`). Stage 3 therefore needs, before it ships:
- **Bug 165's fix:** each slot carries a digest of the body. Required for any group-format challenge or
  response whatever the sender's recorded tier, and from senders at the tier for everything else. **Built
  2026-10-13** (PR #100), with the tier `.bodyDigestCapable` (2.0.0, byte 0x09), which this
  section shares.
- **The slot signature required for a challenge,** on a forward-secret slot, whatever tier is recorded.
  `openGroup` accepts an unsigned forward-secret slot from a sender with no tier recorded; every build that sends
  challenges in group format signs. **Built 2026-10-15**, in the prefixed form only (below).
- **The one-to-one path unchanged.** A challenge outside the group format keeps `openIdentityBundle`'s long-term
  reopening. `decryptSealed`'s forward-secret bundles carry no sender binding (finding #8's residual), so a
  challenge it decrypted is never trusted as it stands. **Built 2026-10-15:** see `Authenticated` below.
- **Bug 166's fix:** a response shows a result only if it names a challenge still waiting for that contact.
  **Built 2026-10-13** (PR #102).
- **One send path.** Challenges go through `encryptBundle`, so their slot padding, prekey batch and shard fields
  match a message's, and D5 holds: no piece operations or manifests ride them. **Built 2026-10-15**:
  `encryptBundle` refuses a challenge with other content, or to a contact below the tier.

**Review of the build plan, 2026-10-14.** Two changes, both built 2026-10-15:
- **The trusted path can't be fed anything else.** `openGroup` returns a challenge or response as
  `IdentityChallenge.Authenticated`, whose initializer is private to `Contact+Manager.swift`, and runs the
  challenge-only checks (digest, signature) where it builds one. `Coordinator.handleAuthenticatedChallenge` takes
  only that type, so an envelope from `decryptSealed` can't reach the path that skips the long-term reopening;
  it goes to `handleInboundChallenge(bundle:…)`, which reopens.
- **The prefixed signature only.** A group-format challenge comes from a 2.0.0 build, which signs the prefixed
  form for any recipient at 1.10.2 or later, so `verifySenderEphemeralSignature`'s bare arm is refused for
  challenges (`acceptsBareForm: false`).

Also checked then and found sound: a sender picks the format by the recipient's recorded tier, which only rises;
old-format challenges stay accepted from contacts at the tier, since our record can lag their update, and they
need a long-term key as today; a replay re-prompts only within the hour's window, as today; challenge files are
named like message files, sent messages aren't stored, and prekey records are a fixed size, so a challenge send
leaves the same traces as a message. Refusing a challenge in a bundle with more than one slot was rejected: the
slot list isn't under the digest, so anyone handling the file could add one and get the challenge refused.

Still open, needs a decision: challenges are recognisable by size whatever key seals them (Bug 167), so the
format change alone doesn't stop them standing out.

---

## 4. Alternatives

### 4.1 Batch size and refill threshold (D4)

**Decided 2026-10-06: batches of 15, refill threshold 5, for v2.0.0.** 50/15 stays open, to be revisited
only with a measurement from an iPhone 11 that holds no real data.

*Why 15/5 without a device number.* CryptoKit's Enclave generation does the same Enclave work as today's
keychain path, without the keychain write; on the Mac's Enclave it was faster (18 ms against 29 ms for 15).
Today's path already runs on iPhone 11s in production, on the receive path. So 15/5 under D9 is very likely
no slower than what ships, which is the bar. 50/15 is about 3.3 times that work on the main actor, and the
Mac's Enclave can't stand in for an A13's. Running the measurement on a phone with real data was ruled out:
a hosted test run installs a Debug Occulta over the real install and starts it against the real data.

Proposed 2026-10-06: a batch of 50 with a refill threshold of 15, against today's 15 and 5. Recorded as open,
to be decided once Enclave key generation time on an iPhone 11 is measured.

**Changed by D9 (§9), the same day.** Prekeys leave the keychain, so step 17b's padding no longer covers them
and the duress-coverage rows and bullet below no longer apply. What remains is latency and size. They are
kept as written, because they record why the question was first tied to the padding range.

**Gain.** Refilling before running out (§3.3) keeps a two-way conversation on one-time keys whatever the batch
size. A larger batch helps only one-way stretches: at 15/5 one gets 5–20 one-time keys before the last-resort
key, at 50/15 it gets 15–65. So up to about 45 more messages per one-way stretch get full forward secrecy
instead of the temporary key's "30 days or more" on the recipient's device (§3.1, §7). How long one-way stretches are is not measured.

**Cost.**

| | 15 / 5 | 50 / 15 |
|---|---|---|
| Peak Enclave keys per contact (`T` + batch + up to 3 last-resort keys) | 23 | 68 |
| Hidden contacts covered by a 32–128 padding range, by the spec's arithmetic ((128 − 32) ÷ peak) | ~4 | ~1 |
| Padding maximum needed to cover about four hidden contacts | 128 | ~300 |
| Batch size, sealed in every message until a key from it is used | ~2.2 KB | ~7.4 KB; up to ~240 KB in a 32-member group send |
| Enclave keys generated when a message arrives | 15 | 50 |

Two costs decide it:
- **Duress coverage.** Step 17b's padding hides hidden contacts only while their prekeys fit inside the random
  range. Keeping coverage at 50/15 means roughly three times the dummies, and their generation time is the
  unmeasured number.
- **Latency.** A batch is generated on the receive path (`decryptSealed`, `openGroup`), which runs on the main
  actor. Fifty Enclave generations there may stall the screen as a message opens; the same measurement shows
  whether it does.

**How to revisit 50/15 (after D9).** Measure CryptoKit Enclave key generation on an iPhone 11 with no real
data on it:
- if 50 generations don't visibly stall a message opening, 50/15;
- if they do, 25/10 or 15/5, or generate off the main actor;
- if even 15 stall it, that is the case for D9's software-key fallback, which needs the owner's explicit
  sign-off (§9).

The per-contact peak still sets the size of the record field that holds the blobs (§9, fixed-width).

**Measurement test:** `PrekeyGenerationMeasurementTests` (`OccultaTests/Forward+Secrecy/`). It asserts that a
CryptoKit Enclave key leaves no keychain item, and attaches timings as `prekey-measurement.txt`. Its header
has the commands for an iPhone 11 run.

*First run, 2026-10-06, Simulator on Apple Silicon (the Mac's Enclave). Not the deciding numbers:*

| | Result |
|---|---|
| Keychain batch of 15 (today) | 29 ms |
| CryptoKit Enclave key | median 1.1 ms, p90 2.2 ms; batch of 15: 18 ms, batch of 50: 63 ms |
| Software key (fallback) | median 0.35 ms; batch of 50: 18 ms |
| `dataRepresentation` size | 143 bytes, every key |
| Opening one message: keychain lookup + ECDH (today) | median 1.7 ms |
| Opening one message: rebuild from blob + ECDH (D9) | median 0.6 ms |
| CryptoKit key leaves a keychain item | No (asserted, with a positive control) |

At 143 bytes per blob, a fixed-width field holds about 3.3 KB at the 15/5 peak of 23, or about 9.7 KB at
the 50/15 peak of 68.

### 4.2 Double Ratchet — rejected

The textbook answer. Here it costs more than it gives:
- **Its chain keys are software keys** in the database. An image of the database holds them. Prekeys are
  Enclave keys, absent from every image and gone for good once deleted (`PASSPHRASE_LAYER_KEYS.md` §2, "Why
  prekeys stay in the Enclave").
- **The transport is files**, through messengers, out of order or lost. That needs storage for skipped
  message keys, and a state mismatch leaves messages unopenable.
- **What it adds over this design is post-compromise recovery.** A batch from the recipient already re-keys
  the pair, and Enclave keys can't be copied off a seized phone.

---

## 5. Compatibility

New fields are optional and ride inside the sealed payload. Behaviour changes only where both sides are new.

| | Sender new | Sender old |
|---|---|---|
| **Recipient new** | Everything here | Old sender ignores `lastResort` and `id`, replaces its store, falls back to long-term when out. The recipient answers long-term bundles as today. Retirement still works (§3.1). |
| **Recipient old** | Old recipient's batches have no `lastResort`, so the sender falls back to long-term when out. Batches without an `id` use the date rule. | Unchanged |

**Downgrade (D6, decided 2026-10-07).** A contact who sent us a last-resort key and then installs an older
build can't open bundles sealed to it: their build looks up the derived `prekeyID` and finds nothing. The
recorded version can't detect it, since it only ever rises. Downgrades on iOS need TestFlight or a sideloaded
build.

**Decided: rule it out by release order.** Last-resort keys (stage 2) ship no earlier than the release that
does v2.0.0's one-way migration: rollout stage 3, the contacts slice, which D9 already ties prekey storage to.
`ROLLOUT_PLAN.md` holds that "migrations are one-way. An older build can't read resealed data." So any build
that can issue a last-resort key has migrated, and any build too old to understand one can't read the migrated
database at all. A contact who forces such a downgrade has an app that can't read its own data. That is the
rollout plan's existing consequence, and nothing about it comes from this design. Only TestFlight testers
moving between pre-release builds could meet the narrower failure.

**Release fixed 2026-10-14:** the prekey refactor (stages 1 and 2, with Bugs 165 and 166) and the contacts slice
both ship in 2.0.0, so the order holds within one release (`ROLLOUT_PLAN.md`, release mechanics).

**Rejected: a "last reported version" marker for this decision.** Every message carries `appVersion`, so a
second, overwritable marker could stop us sealing to the temporary key once a contact reports an older build.
It would hand a lever to anyone with temporary use of the contact's identity key, such as someone holding
their unlocked phone or malware on it. One planted "old version" message would move everything we send them
afterwards from their prekeys to the long-term key, openable from either phone, ours included, with no time
limit. The D2 indicator would show it, but that is a warning, not a protection. Its only benefit is to
TestFlight and sideload users. The rejection covers this use only. Bug 83's remedy uses the same kind of
marker for the signature-prefix choice, where a forced downgrade only means signing the bare form, and that
remains valid.

**New capability tier: `.bodyDigestCapable`** (2.0.0, marker byte 0x09; named 2026-10-13), added with Bug 165's
fix and shared by §3.4(a). §3.1 and §3.3 need none: a batch's own fields say what its sender supports.

## 6. Interaction with v2.0.0 step 17

**Changed by D9 (§9), 2026-10-06.** Prekeys move into the contact's sealed record as Enclave blobs, so 17b's
random tags and padding no longer apply to them. The per-batch records live in the record alongside the blobs,
and the "padding range" and "pruning deletes Enclave keys" bullets below describe the keychain design D9
replaced. 17a is unchanged: the identity key stays in the keychain.

- **17b's random tags and the map in the contact's record** are where this design keeps its per-batch records:
  which keys belong to which batch, which is the last-resort key, retirement times, and accepted batch IDs. Design the record format once, for both.
- **17b's padding range** has to account for the new per-contact count. During a grace period, a contact
  holds up to `T` keys of the old batch, the 15 of the new one, and up to three last-resort keys. At `T = 5`
  that is about 23, against about 15 today. With Bug 156 fixed, the count is also bounded, which it isn't today.
- **17a's per-contact secret** is mixed into every derivation, so last-resort bundles need the contact's
  record just as one-time ones do. This design adds no path that needs only the passcode.
- **Pruning deletes Enclave keys.** That is the "prekeys appearing and disappearing" item step 17 already
  lists as open. Retirement adds deletions that follow the contact's traffic, as consumption already does.
  It adds no new kind of change.

## 7. Forensic and coercion review

| Observer | Today | After |
|---|---|---|
| Holds the `.occ` files | Sees which bundles are long-term: the first message, ~1 in 16, challenges | Long-term only to or from older builds, and before a new contact's first reply. Last-resort bundles look like one-time ones. With §3.4(a), challenges don't stand out by key; they still do by size (Bug 167, open). |
| Images the keychain | ~15 keys per contact plus an unbounded number of leftovers (Bug 156), each with a creation date | No prekey items once legacy keys retire (D9) |
| Images the device repeatedly | Keys disappear as messages are read | Rows change, covered by step 4 as any other write (D9) |
| Coerces an unlock at a duress depth | Sees the forward-secrecy indicator for contacts at that depth | The same. The indicator must not depend on depth. |

**The compose indicator (D2, decided 2026-10-06; colour and wording signed off 2026-10-07).**
`SecrecyIndicator` predicts how the next send will be sealed. Received messages carry no label today. It gets
a **third state, in its own colour**, for when we hold only the contact's last-resort key, and **every state
carries a description**, always shown, so the user can see before sending whether to hold back sensitive
material.

**Layout.** The indicator moves to its own line, below the bundle size and the Encrypt button, which it shares
a line with today. The description sits under the indicator. Neither is behind a tap.

| Colour | Label | When | Description |
|---|---|---|---|
| `occultaVerified` (green), unchanged | Single View · Forward Secret | We hold a one-time key | Once they open it, their phone can no longer open saved copies. |
| New blue token (mockup `#3D74A8`) | Multiple Views · Temporary Key | Only the last-resort key | This message can be opened by anyone who gets into the recipient's device for 30 days or more, until the temporary key expires. Wait for their reply before sending anything sensitive. |
| `occultaWarn` (amber), unchanged | Multiple Views · Long-Term Key | Neither | This message can be opened by anyone who gets into either device, yours or theirs, with no time limit. Hold back anything sensitive. |

*Why blue and not red.* `occultaDanger` (`#D04840`) is nearly the Encrypt button's `occultaAccent`
(`#D34F2C`), so a red dot beside it doesn't read as its own state. Keeping the long-term state amber also means
contacts on older builds don't turn alarming when this ships. Blue alone doesn't say "less safe than green";
the label and description carry that, which they have to do anyway for colour-blind users.

*Why each sentence is worded as it is.*
- "Single View" holds because received messages aren't stored after they're closed (message history is
  deferred, `Message Persistence/FINDINGS.md`). **If message history ships, this label must change.** "Their
  phone can no longer open saved copies", not "nobody can": an image taken before they opened it may still
  work (§9, finding 2).
- "30 days or more": the temporary key retires only when you next send them a message using their new batch,
  plus 30 days (§3.1, D1).
- "Either device, yours or theirs": the long-term key comes from both identity keys, so either phone can derive
  it.
- "Anyone who gets into": the description is a warning about exposure, not a note that the recipient can view
  it again.

*When the long-term state still happens.* Older-build contacts once their one-time keys run out; contacts who
have updated but not yet sent a batch from the new build; and the edges (a stranded version marker, a
downgrade under D6, a reset of our stored copy of their keys), and every new contact until their first reply,
since seeding at the exchange (stage 5) is deferred.

**Built 2026-10-12** (stage 2, 4/4): `SecrecyIndicator` in `ComposeHeroV3.swift`, fed by
`ContactManager.nextSendSecrecy(for:)`, which chooses as `encryptBundle` does, so a last-resort key held for a
contact below the group format shows the long-term state, since that is what the message will use. The blue is
`Color.occultaTemporary`.

The description is plain language, with no claim beyond what the mode delivers (register §E). The state is
per contact and doesn't depend on depth, so a coercer at the compose screen learns at most that the contact
hasn't sent a batch recently, which today's amber state already shows. It is designed together with v2.0.0
step 7, which adds post-quantum status to the same indicator.

All new state lives in the contact's encrypted record. Nothing goes to `UserDefaults`, the filesystem, or any
other OS store (v2.0.0 step 9).

## 8. Stages, tests, migration

Each stage ships with its tests and a migration that loses no message. Enclave-backed tests use
`.enabled(if: secureEnclaveAvailable())`, since they create prekeys through `PrekeySecretsManager`.

**Stage 0 — tests on today's code (Bug 160). Done 2026-10-08:** `PrekeyReplenishmentTriggerTests.swift`, Bug 159
fixed; full suite 985 tests, 0 failed, 6 skipped (all `KeychainMigrationSETests`). End to end through `decryptSealed` and `openGroup`: a long-term
bundle creates a pending batch; a forward-secret bundle clears it; the full cycle back to forward secrecy.
These pin current behaviour before anything changes. Also fix Bug 159 (generate after the last check).

**Stage 1 — prekeys into the record, per-batch records, retirement, batch IDs (D9; Bugs 156, 157, 158, 161).**
D1 and D9 are decided; the three points below were settled 2026-10-08.
- *Shape (decided 2026-10-09):* a value and two workers, after reviewing how Signal-iOS and libsignal split
  prekey work.
  - `PrekeyRecord` is the value: data only.
  - `PrekeyRecordCodec` owns the 16 KB format and reading today's JSON. It is lossless: it never drops data, and
    throws if a record exceeds capacity, which can only mean a broken invariant.
  - `PrekeyBookkeeper` owns the rules: oldest-first, batch IDs, Bug 157, retirement, the sweep, and the size
    limits, eviction included (below).
  - Both workers are stateless structs and pure, so their tests need no Enclave.
  - `PrekeySecretsManager`, renamed from `PrekeyManager`, keeps only the Enclave and keychain work.
  - `ContactManager` is the only reader and writer of the record: it loads, calls the workers and the Enclave,
    stores, saves and flushes the log.
  - `Contact.Profile` only stores the field; its prekey helpers go. The compose indicator asks `ContactManager`
    instead of the profile. The live screen is `Contact.DetailsV2`; `ContactDetailV3` is never constructed.
- *Change:*
  - **Record** (`PrekeyRecord`, built 2026-10-09). Our own batches: ID, created and retired times, an
    `isPending` flag, and each key's 16-byte ID and 143-byte Enclave blob. A key's public key isn't stored: it is
    derived from the blob when the pending batch is sent, 0.2–0.3 ms a key and 3–6 ms for a batch of 16 on the
    Simulator across runs (decided 2026-10-11; an iPhone figure is still needed, from the TestFlight run). Only a pending batch
    carried over from before stage 1, whose keys have no blob, stores public keys. The size budget still leaves
    room to store them, so that if a device shows deriving is too slow, storing them again, or caching them in
    memory, needs no format change. Their
    batches: each batch's ID and its keys' IDs and public keys. The IDs of batches already accepted, the date
    rule's last date, and `legacyKeys`. The pending batch is marked by `isPending` on its own batch,
    not referenced by ID: a pending batch carried over from today's format has no ID and must keep travelling
    without one, since a peer that accepted it under the date rule would accept it again if it reappeared with
    one. The bookkeeper keeps at most one batch pending.
  - **Legacy keys are not listed in the record (decided 2026-10-09).** Our prekeys from before stage 1 are
    keychain Enclave keys, and the keychain never returns an Enclave key's wrapped blob, so they can't be moved
    into the record: they stay in the keychain until retired. A message naming a prekey ID the record doesn't
    hold is looked up in the keychain; deletion goes by the contact's tag prefix. The one exception is a pending
    batch carried over from today's format, which still has to be sent: it stays an own batch whose keys have no
    blob. An earlier plan listed every legacy key as a "batch 0" with an `isLegacy` flag; it was dropped as
    redundant (a missing blob already says "keychain") and as space the record doesn't need to spend.
  - **`legacyKeys` (decided 2026-10-09; a three-state field since the bookkeeper was built).** When the
    contact first uses a key from one of our record-held batches, the legacy keys we issued them are retired; the
    sweep deletes them by tag 30 days later (D1). States: `none` (a contact added after stage 1, or deleted),
    `inUse` (every record converted from today's format starts here), `retired(since:)`. A plain date was the
    first form; it couldn't say the keys were already gone, so every later sweep would delete by tag again, and
    clearing it would read as "not retired yet" and be set again by the next message. Three states delete exactly
    once. It is per contact because each contact switches at a different time. Alternatives rejected: deleting
    legacy keys only when consumed leaves unused ones forever (Bug 156); deleting at the switch loses messages
    still in transit; one deadline for everyone breaks rarely-writing contacts who still hold legacy keys;
    waiting for our first record-held batch to expire is safe but one batch late, and never happens for a contact
    who stops before a second batch. Legacy tags name the contact in the keychain (step 17's leak), so they should
    go as early as is safe.
  - **Fixed size (Bug 161).** The record is encoded in a compact binary layout and padded to a fixed 16 KB
    for every contact, so its length never tracks activity.
  - **Size limits, eviction in the bookkeeper (decided 2026-10-09, corrected 2026-10-11).** Overflow is made
    impossible by construction rather than handled by the codec. The bookkeeper enforces, at the only moments the
    record grows: at most 48 of our own keys (pending, current and retired leftovers, plus last-resort keys from
    stage 2), deleting the oldest retired keys when installing a batch would exceed it; inbound batches of at most
    15 keys with key IDs of at most 36 bytes (a UUID string), anything larger making the batch malformed; at most
    8 accepted batch IDs. Stage 1 holds one inbound batch, since accepting replaces; the budget allows two, for
    stage 4's append. Every field then has a maximum size, but the limits bound keys, not the entries they sit
    in, and each own-batch entry costs about 45 bytes beyond its keys. So the worst case is 48 own keys in as
    many entries as they can form: the pending batch, then 33 one-key entries, which a chatty contact losing one
    file per batch leaves within 30 days. With two full inbound batches it measures 15,683 bytes, and a test
    encodes that record within 16 KB with at least 512 bytes to spare, counting the pending batch's public keys as
    stored, though they are now derived. It fits because a batch drops its 16-byte ID once delivered: the ID is
    needed only on the wire. Kept, the IDs took the same
    record to 16,508 bytes, past the 16,379 available (found 2026-10-11; it needed about 30 batches in 30 days).
    - **With stage 2's last-resort keys** (one per own batch, counted in the 48, and the contact's one) the same
      shape, now the pending batch's 16 keys plus 32 one-key entries, measures 15,874 bytes. The test's margin
      went from 512 to 256 bytes to fit it rather than giving up the room kept for storing public keys again
      (decided 2026-10-11): any per-key field across 48 keys is still well over 256. Counting public keys as
      derived, as the code does, about 1.5 KB is left.
    - **Corrected 2026-10-11.** The limits were first 30 keys per inbound batch and 64-byte IDs, with the worst
      case put at 13,307 bytes. That figure came from a test fixture with 16-key batches and one repeated ID,
      which a binary plist stores once. Measured with distinct values those limits need 19,751 bytes, past
      16 KB with two batches. Stage 1 still fitted (one batch: 15,152), but stage 4 would not have. No build
      sends more than 15 keys or anything but UUID IDs, so the tighter limits refuse nothing real; the launch
      migration drops a carried-over batch outside them.
    - **Only retired keys are evicted (decided 2026-10-11).** Keys not yet retired are the pending batch and the
      one before it, at most 2 × 15, so evicting retired keys alone always makes room. The fallback that evicted
      keys still in use when that wasn't enough could not run, and if it ever did it would silently lose every
      message the contact sealed to them; it was removed, and a test pins the two-batch bound so a stage that
      changes it (stage 2's last-resort key) has to do so on purpose. Evicting a retired key loses only a file
      sealed before the contact moved on and not yet opened, and only when more than 18 such keys are waiting.
    - **No retiring of skipped keys within a batch (rejected 2026-10-11).** Since the contact uses keys oldest
      first, using key 7 shows keys 1–6 were taken earlier; retiring them then would start their 30 days without
      waiting for the batch to retire, closing part of Bug 156's residual. Rejected: it splits a retired entry off
      the batch at each skip, the contact controls the skips, and every entry has a fixed cost, so a contact
      sealing to every other key could fill the record in about 75 messages. The window it closes needs a copy of
      a file lost in transit and the unlocked phone. The skipped keys stay with their batch and retire with it.
    Eviction in the codec
    was rejected: a codec should translate without loss, the rule would sit apart from every other rule about
    which keys exist, and keys would vanish whenever a record happened to be saved.
    It is also never null: an empty fixed-size record is written when the contact is created, because a null
    field (today, until the first message) tells contacts who've exchanged messages from those who haven't,
    with no key needed. Built 2026-10-10, in both places a contact is created (`save(contact:)` and
    `createContacts(from:)`).
  - **Wire.** `PrekeySyncBatch` gains an optional 16-byte `id`, with new interop vectors; batches without one
    keep the date rule. Built 2026-10-09: omitted from the encoding when `nil`, so every existing vector kept
    its bytes, and two new ones (`payload.prekeyBatchWithID`, `recipientPayload.prekeyBatchWithID`) each differ
    from their base vector by exactly the `id` field. The bookkeeper rejects an ID that isn't 16 bytes: the
    sender chooses it and the record stores it.
  - **Generation.** 15 CryptoKit Enclave keys, the same access control as today, blobs into a new own-batch
    record. Built 2026-10-09 (`PrekeySecretsManager.generateEnclaveKeys`, installed by
    `ContactManager.installFreshBatch`); it stays after every check that can reject the bundle (Bug 159).
  - **Lookup.** The receive path checks the record's blobs first, then the keychain for legacy keys. The key
    manager's forward-secret derivation splits into "raw shared secret" and "session key from it", so a
    CryptoKit key and a `SecKey` go through the same derivation. Built 2026-10-09: the receive path takes a
    `PrekeyPrivateKeys`, which `SenderPrekeys` implements over the sender's record and the keychain.
  - **Where it is read.** `ContactManager.prekeyRecord(for:)` reads the new field only. Between the wiring commit
    and the migration commit it fell back to the old field in today's format; the migration commit removed that.
  - **Consumption.** Removing a blob from the record is saved immediately, before anything that can still
    reject the bundle, as the keychain delete was (§2.2). The write-ahead log is then checkpointed, so the
    consumed blob doesn't survive there until SQLite's next checkpoint. Built 2026-10-09: `SenderPrekeys`
    applies the bookkeeping below at the same moment and saves both together, so a bundle rejected after its
    slot opens still delivers the pending batch it used (Bug 157) and retires older keys. That is the same
    fail-secure trade as consumption itself: only the holder of our batch can open the slot, and all it gains is
    retiring our keys early.
  - **Bookkeeping.** The pending batch clears only when the key used belongs to it (Bug 157). The first use of
    a newer batch retires older ones, and the first use of any record-held batch retires the legacy keys (`legacyKeys`). A
    sweep deletes retired blobs, and the contact's legacy keychain keys by tag, 30 days after the respective
    retirement, on receipt and at unlock for the contacts that depth can read (D1, Bug 156). Built 2026-10-10
    (`ContactManager.sweepPrekeys`): at unlock it covers the contacts visible at the authenticated depth, runs at
    every depth, and is flushed by the checkpoint every unlock already takes. **On receipt (changed 2026-10-15,
    found in review of PR #110):** the sweep is applied to the record the open uses, so nothing past its grace
    period opens the bundle, and it's written with the record once a slot has opened (at once for a one-time key,
    else when the bundle has passed every check), and flushed. A file that opens no slot writes nothing, so an
    unauthenticated file naming a contact causes no save, flush or keychain delete; what it would have deleted,
    the next authenticated receipt or the unlock sweep deletes. D1 itself (30 days by time, on receipt and at
    unlock) is unchanged. Inbound batches
    are dropped by ID (Bug 158). Accepting a batch still replaces the keys held from that contact, as today;
    appending is stage 4's.
  - **No manifest of live keys (rejected 2026-10-10).** The record keeps keys the contact may or may not still
    hold, so the contact could report which of ours it holds and we delete the rest. Rejected. Our keys in the
    record are of three kinds: live (unused, in their store), used (sealed to a message we haven't opened), and
    discarded (dropped unused when their store was replaced). A manifest can only identify the discarded ones,
    and those expose nothing, since nothing was sealed to them; the record's fixed size means they leak nothing
    either. The used ones are the forward-secrecy exposure, and the contact can't report on them: it knows it
    used a key, not whether the file arrived. Against that small gain: deleting whatever a manifest omits would
    delete a whole live batch whenever a manifest written before the contact received that batch arrived late;
    its length would track activity unless padded; and it is a wire change older builds don't send. Removing
    what creates discarded keys is better: stage 4's append (so the threshold must not ship ahead of it), Bug
    155's decided fix, and older builds as they update.
  - **Contact deletion.** The record is overwritten with filler of the same size, since the row is only
    soft-deleted, as well as deleting legacy keychain keys. Built 2026-10-10: the filler is the sealed empty
    record, for the reason `deleteContact` seals benign depth stamps rather than random bytes: the rest of the
    row still decrypts, so a field that didn't would read as something deliberately destroyed.
- *Migration (decided 2026-10-09):* **one pass over every contact row at launch, as the first step of the
  contacts slice's one-way migration, before records are resealed per depth.** Every record is readable then,
  because all are sealed under the same local DB key, so the pass treats every row alike.
  - **Lazy migration was rejected.** Whether a row is migrated is visible without any key (variable JSON
    against a fixed 16 KB record, or null against present). Converting a row only when its record is first
    opened would, after the reseal, leave hidden contacts, readable only at their own depth, as the rows still
    unconverted while the user spends time at a duress depth.
  - **The record moves to a new field** on `Contact.Profile`; `forwardSecrecyEncrypted` is set to `nil` on every
    row in the same pass, so it is uniformly null and leaks nothing. The old field is made `private`, so nothing
    reads or writes it again outside the migrations, which reach it through `retiredForwardSecrecyEncrypted`
    (changed 2026-10-10 from `@available(*, deprecated)`: `@Model`'s generated schema names every stored
    property, so the deprecation warned on every build, where it would have been ignored; `private` makes any
    other use a compile error instead). The new field is never null: written empty at contact creation,
    overwritten with same-size filler on deletion.
  - **Built 2026-10-10** as `DatabaseMigration.migratePrekeyRecords`, in the launch migrations after
    `migrateToV2`. The per-depth reseal doesn't exist yet, so "before the reseal" is a constraint on that work:
    it must run after this pass. What each row gets:
    - A live row's record is converted by the codec. One that won't decrypt, decode or fit in 16 KB (nothing
      bounded an inbound key ID before stage 1) becomes empty with `legacyKeys` in use, as an unreadable record
      is read at run time: the keys held from that contact are lost until their next long-term message. No old
      record means no message was ever exchanged: empty, no legacy keys.
    - A soft-deleted row gets an empty record, by readability as the deleted rows' depth stamps are scrubbed:
      sealed when its `deletionToken` decrypts, random bytes at the sealed size when it doesn't.
    - A row still on the v1 scheme is skipped and `migrateToV2` retries it first: its old field isn't under the
      current key yet, so converting it would discard it. Such a row already shows through its plaintext
      `encryptionScheme`, so its missing new field adds nothing.
    - A row with a new field and no old one is left byte-identical, so ordinary launches rewrite nothing.
  - Existing keychain prekeys stay in the keychain, unlisted, until 30 days after they retire (`legacyKeys`); after
    that no prekey keychain items remain for that contact. The prekeys we hold for them become one inbound batch
    with no `id`, and a pending batch becomes a pending own batch with no `id` and no blobs. Messages already
    sealed to keychain prekeys still open throughout.
- *Shipping order:* a build that stores blob prekeys can't be downgraded without losing the messages sealed
  to them, as with D6. Stage 1 can be built and merged now but ships no earlier than the one-way migration
  release (rollout stage 3, the contacts slice), which D9 already ties it to.
- *Commits:* the key-manager split (pure refactor, existing tests unchanged); fixed-size record (Bug 161);
  record format and wire `id` with interop vectors; generation, lookup, consumption with its immediate save and
  checkpoint, Bug 157 (done 2026-10-09, with the compose indicator moved to `ContactManager` and the profile's
  prekey helpers removed); retirement, sweep and the contact-deletion overwrite (done 2026-10-10, with the
  empty record at creation); migration (done 2026-10-10).
- *Tests:* creating a CryptoKit Enclave key adds no keychain item (count before and after); a blob-backed prekey
  opens a message and its blob is gone from the record afterwards; a bundle rejected after it opens still leaves
  its blob deleted and saved; the record encodes to exactly 16 KB empty and with every limit reached at once;
  installing a batch past the own-key limit deletes the oldest retired keys first and never a key not yet retired,
  and those keys never exceed two batches; an inbound batch with too many keys or an over-long key ID is rejected; the codec throws rather than trims a record past
  capacity; a newly created contact, one never written to, and a deleted one all have the
  field present at that same size; after the migration pass every row's new field is present at 16 KB and every
  row's `forwardSecrecyEncrypted` is `nil`, whatever state the row started in; a deleted contact's record holds no blobs; a legacy keychain prekey and a
  record-held one both open messages; out-of-order arrival keeps the pending batch (157); an older-dated batch
  with a new `id` is accepted, and a repeated `id` is dropped (158); retired keys are deleted after the grace
  period and not before; a message sealed to a retired key within the grace period still opens.

**Stage 2 — last-resort key (§3.1).** D2's indicator and D5's replay guards ship with it. Ships no earlier
than the release that does the one-way migration (rollout stage 3, D6), and never ahead of stage 1. Both ship in
2.0.0 (decided 2026-10-14).
- *Commits:* record and wire (done 2026-10-11: `PrekeySyncBatch.lastResort`, the derived prekey ID in
  `OccultaFormats` with a known-answer test, our last-resort key on each own batch and the contact's on the
  record, generated and sent with every new batch but not yet used, two new interop vectors); sending and
  receiving with the bookkeeping table (done 2026-10-12, with D5's first guard: piece operations and manifests
  off last-resort slots, on both sides; a single-recipient bundle naming a last-resort key is rejected); D5's
  remaining guards (done 2026-10-12: G1, and the receiver's drop extended to one-to-one bundles' shared payload,
  Bug 164; G2′ and the replay matrix dropped for Bug 163's lineage, deferred); D2's indicator (done
  2026-10-12).
- *Migration:* pairs get a last-resort key with their next batch. (No custody-row migration: G2′ was dropped,
  2026-10-12.)
- *Tests:* sender falls back to last-resort, not long-term, when out; the derived `prekeyID` differs per
  bundle, matches the UUID format, and never equals the last-resort key's own ID; recipient opens it without consuming it; the three bookkeeping rows in
  §3.1; an old-format batch leaves the sender on long-term; interop vectors for a batch that carries it; the
  indicator resolves to each of its three states from the matching key state (one-time key held, only the
  last-resort key, neither) and to the same state at every depth. Replay (D5): no piece operation or
  manifest is attached when sealing to the last-resort key; a last-resort slot carrying them has them dropped;
  a repeat delivery sealed to an older last-resort key generates no batch; a repeated `.replace` stores
  nothing (G1); a one-to-one bundle's shared piece operations and manifest are dropped on a long-term and on a
  last-resort slot (Bug 164). The replay matrix waits for Bug 163.

**Stage 3 — identity challenges (§3.4).** D3 is decided (group format at the new tier). The tier exists:
`.bodyDigestCapable`, from Bug 165's fix. The 2026-10-12 review's requirements are in §3.4.
- *Commits (built 2026-10-15, `v2.0.0/prekey-stage-3`):* receiving (`IdentityChallenge.Authenticated` from
  `openGroup`, the prefixed signature required on a forward-secret slot, the manager's checks shared by both
  paths); sending (the coordinator picks the format by tier, `encryptBundle(identityChallenge:)`, `createChallenge`
  and `respond` take a sealing closure); Bug 155 (`decryptSealed` makes no batch for a challenge); docs.
- *Migration:* none. A challenge already in flight uses the old path, which stays.
- *Tests:* a challenge and its response to a new-tier contact go in group format and verify end to end; with
  no prekeys held for the contact, they still go through, on the long-term slot; to an older contact,
  long-term as today; a group-format challenge with a bad or missing ephemeral signature is rejected, including
  from a contact with no tier recorded; a long-term challenge from an older contact creates no prekey batch (Bug
  155). From the 2026-10-12 review (§3.4): a challenge in a body rewritten by another recipient is rejected (Bug
  165); a challenge in a one-to-one forward-secret bundle is rejected; a reopened response shows nothing, and one
  naming our challenge with a bad signature still fails (Bug 166). Built in `IdentityChallengeGroupFormatTests`,
  with: our answer goes as a message and passes on the challenger's phone; a challenge goes to the last-resort key
  once the one-time keys are out; a long-term challenge from a contact recorded at the tier is still accepted;
  `encryptBundle` refuses a challenge with other content or below the tier, before taking a key; the checks after
  opening still run on an authenticated challenge. The forward-secret cases need a prekey this device holds, so
  `IdentityChallengeGroupForwardSecretTests` is Enclave-gated.

**Stage 4 — refill and append (§3.3).** D4 is decided (15/5).
- *Commits (built 2026-10-15, `v2.0.0/prekey-stage-4`):* append (`accept` appends, two batches at most, a third
  drops the oldest, decided 2026-10-15); refill (`needsRefill`, wired into `replenish`, the keychain-count check
  removed); conversation tests; docs.
- *Migration:* none beyond stage 1's.
- *Tests:* refill fires at `T`; the sender appends and uses the oldest first; the first use of the new batch
  retires the old one; a two-way conversation of 100 messages never reaches the last-resort key. Built as unit tests
  (`PrekeyBookkeeperAppendTests`, `PrekeyBookkeeperRefillTests`) and two layers of conversations: end to end, two
  phones exchanging real bundles (`PrekeyConversationTests`, Enclave-gated) — alternating, bursts of 1, 5 and 6,
  bursts of 10, one way, one message in seven lost, out of order, 100 or more keys each way; and through the
  bookkeeper alone (`PrekeyConversationSimulationTests`, on CI too) — the same to 1,000 messages each way, plus
  seeded random runs. Every message opens, both records stay within the fixed size's limits after every step, and
  an in-order conversation leaves no unused key in a retired batch. With refill disabled, or append replaced by the
  old replacement, the tests that should fail do. Added 2026-10-15, on expiry (§3.1, "No key is marked expired"):
  every key a phone holds for the other is one the other still holds unretired, checked after every step through
  40-day silences and sweeps; a retired batch's last-resort key opens for 30 days and is swept after, and a live
  batch's never is. Keeping the old last-resort key on accept, or taking keys newest first, fails them.

**Stage 5 — seed at the exchange (§3.2, v2.0.0 step 6). Deferred out of v2.0.0, 2026-10-07 (§3.2).** When it
returns: D7's sealing as recorded in §3.2.
- *Tests, for then:* both directions between old and new builds; a batch that fails to open isn't stored; a
  cancelled exchange leaves nothing behind; the first message after an exchange is forward secret.

**Expected result** between two current-build contacts after stage 4: no message uses the identity keys once
the contact has first replied; before that, messages to a new contact are long-term and the indicator says so. A
burst of more than `T + 1` = 6 messages between replies may reach the last-resort key for its remainder, and a
one-way run past the keys held does. It is exposed on the recipient's phone only, until
the sender uses a key from the recipient's next batch, plus 30 days; with no reply, for as long as the
recipient keeps the key (§3.1). To measure it, count long-term bundles in a scripted
conversation before and after each stage.

## 9. Where prekeys live — research, 2026-10-06

Raised while working out the padding range (§4.1). `PASSPHRASE_LAYER_KEYS.md` §2 keeps prekeys as keychain
Enclave keys because "only an Enclave key is absent from every image and gone for good once deleted". The
findings below don't support that.

**Findings**

1. **An Enclave key in the keychain is a blob on disk, not a key inside the Enclave.** Apple DTS: "these
   items aren't actually stored on the SE. Rather, they are stored on the device itself, but in a way that the
   item is only available to the SE" ([forum 129402](https://developer.apple.com/forums/thread/129402)).
   CryptoKit's documentation describes the same wrapped form: "an encrypted block that only the same Secure
   Enclave can later use to restore the key" ([Storing CryptoKit Keys in the Keychain](https://developer.apple.com/documentation/cryptokit/storing-cryptokit-keys-in-the-keychain)).
2. **Nothing documents revoking one wrapped key.** Apple's anti-replay protects keybag lockers, passcode
   counters and effaceable storage, and "the key-wrapping key changes every time a user erases their device"
   ([Data Protection](https://support.apple.com/guide/security/sece8608431d/web),
   [The Secure Enclave](https://support.apple.com/guide/security/sec59b0b31ff/web)). Inference, **not yet
   verified on a device**: an old copy of the blob stays usable on that phone until it is erased.
3. **Keychain rows record creation time.** The `keys` table (`v12_keys_class` in
   [`SecItemSchema.c`](https://github.com/apple-oss-distributions/Security/blob/main/keychain/securityd/SecItemSchema.c))
   has `cdat` and `mdat`, set to the current date automatically and returned as attributes, an
   insertion-ordered `rowid`, the public-key hash `klbl`, `tkid` and `agrp`. This settles §4.1's open
   question: yes. **Confirmed on a device keychain 2026-10-06** (the probe below, Simulator on Apple
   Silicon): a prekey created by `PrekeySecretsManager.generateBatch` returns `cdat`, `mdat`, `klbl`, `sha1`,
   `tkid = com.apple.setoken` and the app's `agrp` through the ordinary `kSecReturnAttributes` query.
4. **The keychain doesn't scrub deleted rows.** It runs in WAL mode with incremental auto-vacuum, and nothing
   in Apple's Security source sets `secure_delete`
   ([`SecDb.c`](https://github.com/apple-oss-distributions/Security/blob/main/OSX/utilities/SecDb.c)).
   Forensic tools decrypt keychain rows, `ThisDeviceOnly` included, given the passcode. So a deleted prekey's
   row may survive in free pages or the WAL even in a single later image.
5. **Our database does scrub:** `secure_delete = ON` and a WAL flush after purges
   (`forensic-trace-avoidance.md` S2, `OccultaApp.swift`).

**What follows**

- **A deleted keychain prekey is not gone.** Older images hold its blob, and possibly the current one does too
  (finding 4). If finding 2 holds, the same phone's Enclave will still use that copy.
- **Against an adversary who images the phone with the passcode before a message is opened, and holds the
  phone later, no storage choice gives forward secrecy.** Only erasing the device invalidates old blobs. What
  storage can still do is make using an old copy need more than the passcode, and leave no residue after
  deletion.
- **On those terms, the sealed record beats the keychain on every axis:**

| | Keychain Enclave key (today) | Enclave-wrapped blob in the sealed record |
|---|---|---|
| Copyable off the phone | No | No |
| Old copy usable after deletion | Yes, with the passcode (finding 2) | Only with the passcode **and** that depth's phrase |
| Residue after deletion | Possible (finding 4) | Scrubbed (finding 5) |
| Metadata outside our control | Count, `cdat`, `rowid`, `klbl` | None; our own row design (steps 3–5) |
| Hidden contacts' keys at a duress depth | Listable, and usable with the passcode | Unreadable without the phrase |

**Decided 2026-10-06 (D9): prekeys become Enclave-wrapped blobs in the contact's sealed record**, not keychain
items. They are generated with CryptoKit's `SecureEnclave.P256.KeyAgreement.PrivateKey`, and its
`dataRepresentation` is what the record stores. The key is the same kind of Enclave key as today; only where
its wrapped form is kept changes. Deleting a prekey means deleting its blob from the record, which
`secure_delete` scrubs. CryptoKit saves nothing itself, so the record holds the only copy.

**Why the Enclave and not plain software keys**, which would also live in the record with near-identical code
(`P256.KeyAgreement.PrivateKey`, `rawRepresentation`):

| | Software key in the record | Enclave blob in the record |
|---|---|---|
| Image + passcode + that depth's phrase yields | The raw key, usable on any computer, forever | A blob only this phone's Enclave can use |
| Decrypting a message captured later | The image alone is enough | Needs the phone again, unlocked |
| After the user erases the phone | Keys from the image still work | Every old blob is dead; erasing changes the Enclave's wrapping key |
| Generating a batch | Microseconds | Enclave latency; at 15 keys, no worse than today's keychain path (D4) |

The case that decides it is an adversary who images the phone and gives it back, as at a border. With
software keys, that image plus the phrase decrypts, offline and permanently, any later-collected `.occ` sealed
to a key still live in it. With Enclave blobs they need the phone back.

**Fallback: software keys, only with the owner's explicit sign-off.** If the iPhone 11 measurement (§4.1)
shows Enclave generation stalls the receive path, the fallback is software keys in the record. It is not
adopted automatically on the measurement's result. It needs the owner's explicit acknowledgement that it gives
up the property in the table above, recorded here with the date, before any code uses it.

Consequences:
- Step 17b's random tags and Enclave padding no longer apply to prekeys, and nor does the creation-date
  problem: no prekey keychain items exist to count or date. §4.1 is no longer tied to the padding range; D4
  keeps only the latency and size costs.
- The record field holding the blobs must not vary in size with how many a contact holds. It is fixed-width,
  padded to the maximum, or covered by step 3's filler.
- The row the blobs live in must be covered by steps 3 and 4. Consumption is one more write to it.
- Existing keychain prekeys stay where they are until consumed or retired (30 days, D1). Every new batch goes
  to the record. After the last retirement no prekey keychain items remain.
- `PASSPHRASE_LAYER_KEYS.md` §2's "Why prekeys stay in the Enclave" and items 2–3 (random tags, padding) are
  superseded for prekeys by this section. The Enclave stays; the keychain goes.

**Finding 2 can't be verified through the public API (probe run 2026-10-06).** A one-off probe
(`EnclaveBlobReplayProbe`, deleted after D9 was decided; it always passed, so it had no place in the suite)
created a production prekey, read back what the keychain returns, and tried to rebuild the key from each
returned value with `SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation:)`, before and after
deletion. `kSecReturnData` succeeds with no bytes, no attribute carries the wrapped blob, and nothing returned rebuilds
the key, so the result is inconclusive. That is not evidence an adversary can't recover the blob: a forensic
tool reads the database row directly. Finding 2 stays an inference. D9 was decided on it: if deletion were
final after all, the keychain's one advantage (an old image of a visible contact's prekeys would be useless)
would still not outweigh its unconditional metadata leaks.

## 10. Open decisions

Every design decision below is taken; D7 returns with stage 5. The exposure §2 names (messages before a new
contact's first reply) is open, not accepted. Found since, and **open, needing a decision**, though none blocks a
stage:
- **Bug 156's residual:** a key whose message was lost stays until the contact moves to a newer batch.
- **Bug 167:** identity challenges and responses are recognisable by size, whatever key seals them (§3.4).
- **Making 2.0.0 the minimum sender** (Bug 165): refusing every group bundle without a body digest, which
  closes the rewrite for senders before 2.0.0 and stops those contacts sending anything.

| # | Decision | Where |
|---|---|---|
| D1 | Grace period before a retired batch is deleted. **Decided 2026-10-06: by time, 30 days from retirement** | §3.1 |
| D2 | What the compose indicator shows when only the last-resort key is held. **Decided 2026-10-06: a third state in its own colour, and a description on every state.** Colour (blue middle state, amber long-term) and wording signed off 2026-10-07 | §7 |
| D3 | Identity challenges. **Decided 2026-10-07: group format to contacts at the new tier (a)**; long-term to older contacts as today | §3.4 |
| D4 | Batch size and refill threshold `T`. **Decided 2026-10-06: 15/5.** 50/15 revisited only with a measurement from an iPhone 11 holding no real data | §4.1 |
| D5 | Replay of last-resort bundles. **Decided 2026-10-07: messages may reopen; piece operations and manifests only on one-time keys; trustee guard G1 (no duplicate `.replace`).** *Revised 2026-10-12:* G2′ ("supersedes" field) and the replay matrix dropped; ordering of `.replace` is Bug 163's, deferred. Replay cache, per-owner tombstones, timestamp ordering and a manifest counter rejected | §3.1 |
| D6 | A contact who downgrades after sending a last-resort key. **Decided 2026-10-07: ruled out by release order**: last-resort keys ship no earlier than the one-way migration; both ship in 2.0.0 (2026-10-14). A "last reported version" marker for this decision was rejected as a downgrade lever | §5 |
| D7 | Binding the seed batch. **Moot for v2.0.0: stage 5 deferred, 2026-10-07.** Kept in §3.2 for when it returns: authenticate with a key derived from the words' secret, most likely exchanging prekeys and other setup data after both users confirm the words (owner's note, 2026-10-07) | §3.2 |
| D8 | Target release. **Decided 2026-10-06: v2.0.0**, alongside step 17 (step 6 deferred, 2026-10-07). Ships in the 2.0.0 release, with the contacts slice (2026-10-14) | §8 |
| D9 | Where prekeys live. **Decided 2026-10-06: Enclave-wrapped blobs (CryptoKit) in the contact's sealed record**, not keychain items. Fallback to software keys in the record only with the owner's explicit, recorded sign-off | §9 |

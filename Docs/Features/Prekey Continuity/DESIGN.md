# Prekey Continuity — Design

**Status:** Proposed, 2026-10-06. **Target: v2.0.0** (D8). **Grace period: 30 days** (D1). **Compose indicator: a third state and
per-state descriptions** (D2). **Prekeys as Enclave blobs in the sealed record** (D9). **Batches of
15, refill at 5** (D4). **Identity challenges in group format** (D3, 2026-10-07). Nothing else is decided.
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

Code references are against `7affd76`.

---

## 1. Problem

A message to a contact gets forward secrecy only if we hold one of their one-time prekeys. They can only give
us more by sending us something. So we fall back to the **long-term** mode (`.longTermFallback` /
`.longTermNoPQ`), which derives the key from the two identity keys:

1. **The first message in each direction.** The in-person exchange carries no prekeys.
2. **After 15 messages without a reply.** `PrekeyManager.defaultBatchSize` is 15. A new batch is generated
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
- No message between two contacts on a current build uses the identity keys for its session key.
- A message sent while the sender is out of one-time prekeys is exposed on the recipient's device only, and
  only until the recipient's next batch replaces the key (§3.1, "Without a reply").
- Nothing new is visible to someone holding the files, the keychain, or a coerced unlock.

**Non-goals**
- **Contacts on older builds.** They can't take part; long-term stays their path (§5).
- **Post-compromise security** (a Double Ratchet). Rejected in §4.2.

---

## 3. Design

Four parts, all needed. §3.1 is the one that removes the long-term mode; §3.2 and §3.3 make one-time prekeys
the normal case so §3.1 is rarely used; §3.4 keeps identity challenges from standing out once long-term
bundles are rare.

### 3.1 Last-resort prekey

Each batch carries one extra prekey that may be used more than once. When the sender runs out of one-time
prekeys, it seals to the last-resort key instead of the identity keys.

**Generation (recipient, B).** Generated with the batch, with the same Enclave attributes and tag scheme as a
one-time prekey, so the keychain can't tell them apart. Which of our keys is the last-resort one is recorded
in the contact's record, not in the tag.

**Wire.** `PrekeySyncBatch` gains one optional field, inside the sealed payload:

```
lastResort: { publicKey: 65 bytes (x963), idKey: 32 random bytes }   // absent from older builds
```

Synthesized `Codable` omits a nil optional and ignores an unknown key, so older builds decode a batch that
carries it, and batches without it encode exactly as today; the existing interop vectors don't change. New
vectors cover a batch that carries it.

**Sending (A).** On accepting a batch, A stores its `lastResort` in the contact's record, replacing the
previous one. When `popOldestPrekeyData()` returns nil and a last-resort key is stored, A seals in the normal
forward-secret mode with a fresh ephemeral key, as for a one-time prekey, with two differences:

- the key is **not** removed after use;
- the cleartext `prekeyID` is not a stored ID. It is `HMAC-SHA256(idKey, ephemeralPublicKey)`, truncated to
  16 bytes, with the UUID version-4 and variant bits set, formatted as `UUID().uuidString` formats one.

The `prekeyID` is why the `idKey` exists. A fixed ID would appear in the clear on every bundle sealed to that
key and link them all. The derived ID changes with every ephemeral key, can't be computed without the
`idKey`, and has the same format as a real one. Mode, sizes and the sender's ephemeral signature are those
of a one-time forward-secret bundle, so the two can't be told apart on the wire.

Used only when the bundle goes out in group format (`targetVersion.supportsGroups`), so the
`senderEphemeralSignature` authenticates it. A contact who sends a last-resort key is on a new build, so this
always holds unless their recorded version is stranded; in that case A falls back to long-term, as today.

**Receiving (B).** In `deriveInboundKey`'s forward-secret branch, when no stored prekey matches the
`prekeyID`, B computes the derived ID for each last-resort key it still holds for this sender and uses the one
that matches. There are at most three: the delivered batch's, the pending batch's, and one retired but still
within its grace period. That is one HMAC per candidate and no extra Enclave operation, so a 32-slot group
bundle costs at most 96 HMACs. The last-resort key is **not**
consumed. `findAndOpenRecipientSlot` consumes whatever key opened the slot (its `defer`), so it needs to know
which kind of key it used.

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

**Without a reply.** A last-resort key retires only when the sender uses a key from a newer batch, and only
the recipient can send one. A recipient who never replies keeps the key, and every message sealed to it stays
openable on their phone, for as long as that lasts. There is no better fallback: capping the key's life
would push the sender back to the identity keys, which are exposed on both phones, forever. What the user
can do is wait for a reply before sending something sensitive, which is what D2's indicator is for.

**Replay.** A last-resort bundle opens again if it is delivered again, until its key is deleted. A long-term
bundle opens again forever, so this is no worse than today. A replay cache would stop it, but it would be a
stored record of messages received. **Open, needs a decision (D5).**

### 3.2 Seed a batch at the in-person exchange

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
run out, so a two-way conversation never reaches the last-resort key.

**Refill (B).** When the contact holds `≤ T` unused one-time keys from batches they have received, and no
batch is pending, B generates a batch and attaches it. `T` replaces `PrekeyManager.replenishThreshold`, which
is unused today. **`T` = 5, with batches of 15 (D4, decided 2026-10-06, §4.1).**

The count comes from the per-batch records in the contact's record, not from `remainingCount(for:)`. That
function counts keychain items by tag. It includes keys that will never be used (Bug 156), and it stops
working once tags no longer name the contact (step 17b).

**Append (A).** `syncInboundPrekeys` appends a new batch after the keys already held, instead of replacing
them, and `popOldestPrekeyData()` stays oldest first. That order is what makes the retirement rule in §3.1
work. Cap the store at two batches. `storeInboundBatch` already rejects a batch of more than
`2 × defaultBatchSize` keys.

**Duplicates by ID, not date (Bug 158's fix).** Appending makes the duplicate check matter more: a late copy
of a batch already used would add keys B has already deleted, and messages sealed to them could never be
opened. `PrekeySyncBatch` gains an optional `id` (16 random bytes). A keeps the IDs of the batches it has
accepted, at most a handful, and drops a batch it has seen. A batch without an `id` comes from an older
build and keeps today's date rule. That keeps 158 open for older senders only.

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
  `senderProof` binds the routing fields.
- **Authentication is unchanged in strength.** The challenge was authenticated by long-term ECDH; it is now
  authenticated by an identity-key signature over the slot's ephemeral key. Both need the contact's identity
  private key. The response stays signed by the identity key after the contact approves it.
- **Version gate.** Contacts below the tier keep today's long-term path, unchanged. The tier is shared with
  step 17a's negotiation rather than adding another.
- **Bonus.** Challenge contents, including the typed context note, get forward secrecy instead of being
  openable from either phone indefinitely.
- **Bug 155.** New-tier challenges no longer look like an exhausted sender, so they stop triggering batches.
  Long-term challenges from contacts below the tier still would, so `decryptSealed` also skips batch generation
  when the payload carries `identityChallenge`. That needs Bug 159's reordering first, since generation runs
  before decoding today.

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

**Downgrade.** A contact who sent us a last-resort key and then installs an older build can't open bundles
sealed to it: their build looks up the derived `prekeyID` and finds nothing. This is the same class as Bug 83,
and the recorded version can't detect it, since it only ever rises. **Open, needs a decision (D6).** Downgrades
on iOS need TestFlight or a side-loaded build.

**New capability tier** (name to choose), at the release that ships §3.4(a). §3.1 and §3.3 need none: a
batch's own fields say what its sender supports.

## 6. Interaction with v2.0.0 step 17

**Changed by D9 (§9), 2026-10-06.** Prekeys move into the contact's sealed record as Enclave blobs, so 17b's
random tags and padding no longer apply to them. The per-batch records live in the record alongside the blobs,
and the "padding range" and "pruning deletes Enclave keys" bullets below describe the keychain design D9
replaced. 17a is unchanged: the identity key stays in the keychain.

- **17b's random tags and the map in the contact's record** are where this design keeps its per-batch records:
  which keys belong to which batch, which is the last-resort key, retirement times, the last-resort `idKey`,
  and accepted batch IDs. Design the record format once, for both.
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
| Holds the `.occ` files | Sees which bundles are long-term: the first message, ~1 in 16, challenges | Long-term only to or from older builds. Last-resort bundles look like one-time ones. With §3.4(a), challenges don't stand out. |
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
downgrade under D6, a reset of our stored copy of their keys). New contacts never reach it once stage 5 ships.

The description is plain language, with no claim beyond what the mode delivers (register §E). The state is
per contact and doesn't depend on depth, so a coercer at the compose screen learns at most that the contact
hasn't sent a batch recently, which today's amber state already shows. It is designed together with v2.0.0
step 7, which adds post-quantum status to the same indicator.

All new state lives in the contact's encrypted record. Nothing goes to `UserDefaults`, the filesystem, or any
other OS store (v2.0.0 step 9).

## 8. Stages, tests, migration

Each stage ships with its tests and a migration that loses no message. Enclave-backed tests use
`.enabled(if: secureEnclaveAvailable())`, since they create prekeys through `PrekeyManager`.

**Stage 0 — tests on today's code (Bug 160).** End to end through `decryptSealed` and `openGroup`: a long-term
bundle creates a pending batch; a forward-secret bundle clears it; the full cycle back to forward secrecy.
These pin current behaviour before anything changes. Also fix Bug 159 (generate after the last check).

**Stage 1 — prekeys into the record, per-batch records, retirement, batch IDs (D9; Bugs 156, 157, 158).**
D1 and D9 are decided.
- *Change:* new batches are CryptoKit Enclave keys whose blobs go in a fixed-width field of the contact's sealed
  record. The receive path looks a prekey up in the record first, then in the keychain for legacy keys.
- *Migration:* on first launch, each contact's existing keychain prekeys (by tag) become "batch 0" in the
  record, retired when a key from a newer batch is first used, and deleted from the keychain after the grace
  period. After that no prekey keychain items remain. A's stored `encodedPrekeys` become one batch with no
  `id`. Messages already sealed to keychain prekeys still open throughout.
- *Tests:* creating a CryptoKit Enclave key adds no keychain item (count before and after); a blob-backed prekey
  opens a message and its blob is gone from the record afterwards; the record field's size doesn't change with
  how many blobs it holds; a legacy keychain prekey still opens a message after migration; out-of-order
  arrival keeps the pending batch (157); an older-dated batch with a new `id` is accepted, and a repeated `id`
  is dropped (158); retired keys are deleted after the grace period and not before; a message sealed to a
  retired key within the grace period still opens.

**Stage 2 — last-resort key (§3.1).** Needs D5 and D6. D2's indicator ships with it.
- *Migration:* none. Pairs get a last-resort key with their next batch.
- *Tests:* sender falls back to last-resort, not long-term, when out; the derived `prekeyID` differs per
  bundle and matches the UUID format; recipient opens it without consuming it; the three bookkeeping rows in
  §3.1; an old-format batch leaves the sender on long-term; interop vectors for a batch that carries it; the
  indicator resolves to each of its three states from the matching key state (one-time key held, only the
  last-resort key, neither) and to the same state at every depth.

**Stage 3 — identity challenges (§3.4).** D3 is decided (group format at the new tier). Needs the tier, shared
with step 17a.
- *Migration:* none. A challenge already in flight uses the old path, which stays.
- *Tests:* a challenge and its response to a new-tier contact go in group format and verify end to end; with
  no prekeys held for the contact, they still go through, on the long-term slot; to an older contact,
  long-term as today; a group-format challenge with a bad or missing ephemeral signature is rejected; a
  long-term challenge from an older contact creates no prekey batch (Bug 155).

**Stage 4 — refill and append (§3.3).** D4 is decided (15/5).
- *Migration:* none beyond stage 1's.
- *Tests:* refill fires at `T`; the sender appends and uses the oldest first; the first use of the new batch
  retires the old one; a two-way conversation of 100 messages never reaches the last-resort key.

**Stage 5 — seed at the exchange (§3.2, v2.0.0 step 6).** Lands with 17a and 17b, which change the exchange
and the tags. Needs D7.
- *Tests:* both directions between old and new builds; a batch with a bad signature isn't stored; a cancelled
  exchange leaves no Enclave keys; the first message after an exchange is forward secret.

**Expected result** between two current-build contacts after stage 5: no message uses the identity keys. A
one-way burst past the keys held uses the last-resort key. It is exposed on the recipient's phone only, until
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
   Silicon): a prekey created by `PrekeyManager.generateBatch` returns `cdat`, `mdat`, `klbl`, `sha1`,
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

D5–D7 are open, and none is accepted.

| # | Decision | Where |
|---|---|---|
| D1 | Grace period before a retired batch is deleted. **Decided 2026-10-06: by time, 30 days from retirement** | §3.1 |
| D2 | What the compose indicator shows when only the last-resort key is held. **Decided 2026-10-06: a third state in its own colour, and a description on every state.** Colour (blue middle state, amber long-term) and wording signed off 2026-10-07 | §7 |
| D3 | Identity challenges. **Decided 2026-10-07: group format to contacts at the new tier (a)**; long-term to older contacts as today | §3.4 |
| D4 | Batch size and refill threshold `T`. **Decided 2026-10-06: 15/5.** 50/15 revisited only with a measurement from an iPhone 11 holding no real data | §4.1 |
| D5 | Replay of last-resort bundles: accept until deletion, or keep a replay cache | §3.1 |
| D6 | Handling a contact who downgrades after sending a last-resort key | §5 |
| D7 | Binding the seed batch: sign it (§3.2), or wait for step 8 and send it after confirmation | §3.2 |
| D8 | Target release. **Decided 2026-10-06: v2.0.0**, alongside steps 6 and 17 | §8 |
| D9 | Where prekeys live. **Decided 2026-10-06: Enclave-wrapped blobs (CryptoKit) in the contact's sealed record**, not keychain items. Fallback to software keys in the record only with the owner's explicit, recorded sign-off | §9 |

# v2.0.0 — Passphrase Rollout

**Status:** Proposed, 2026-10-19. The owner went through §8 on 2026-10-19, and again from 2026-10-29 after the
brainstorm of 2026-10-27 to 29 (§1.5). Each decision is marked where it applies and logged in `decisions.md`.

**Decided 2026-10-19:**
- 2, direct derivation;
- 3, the release after 2.0.0;
- 5, every install migrates;
- 10, setup required at once;
- 12, the full list with 7 words;
- 13a and 13b, no suggestion bar, and VoiceOver as in password fields;
- 15a, 15b, 15c and 15d, keys stay in the keychain, and erase deletes the share key.

**Decided 2026-10-29, which replaces or changes earlier decisions:**
- 1, independent spaces replace the 2026-10-15 storage design (§1.5);
- 4 and Rule 4, no probation week and no old store as the way back; the old store is deleted once the reseal is
  verified (§1.2, §3.2);
- 7a to 7d, the coercion gate: lock-off for everyone with one warning, lock-on reseals the current space, coercer-
  created layers dropped at migration only (§1.3);
- 8a and 8b, kept, but the old store waits until every layer has migrated; Rule 2 stands for the migration (§3.1);
- 9a and 9b, no remove-space action; Erase All Data erases the current space only and leaves the install-wide
  keys (§5);
- 11a and 11b, the vault's own key from the space key, with an on-screen Face ID gate (§6);
- 14, no rehearsal feature (§2.5);
- 16, D2 of Bug 171: the Enclave does not take part in every guess;
- 17, the release is 2.1.0, so `release/v2.1.0` and `v2.1.0/` feature branches;
- 18, downgrade after migration is not supported, and the release notes say so;
- 19, Bug 170's leftovers stay in Bug 170;
- no typo check: no checksum and no retype before the first write (§1.5);
- a bundle for a contact in another space is handled exactly like a corrupt file (§1.5);
- 24, that screen says "The contact who sent this message was deleted or cannot be found", the same message as
  for a deleted contact, and today's app refuses a hidden contact's bundle the same way (decided 2026-10-31, not
  implemented);
- 23, the new store file is plain SQLite: every table sealed under a space key, each `WITHOUT ROWID` with a random
  16-byte key and the sealed record, and no SwiftData (decided 2026-11-01, not built; Bug 190);
- 25, whole-space writes: Erase shows nothing about data still held; a rekey and lock-on are part of Bug 120's
  stated limit; a space that migrates later appends noise rows with its batch, how many settled with 21 (decided
  2026-11-01);
- 21, the contact table's noise count: drawn per install, uniformly from 50–1,000, never stored, written at
  migration, at a fresh install's first launch and with a late migration batch, and never after (decided
  2026-11-01);
- 27, the key cache: memory only, and the key and every decrypted record dropped when the app goes to the
  background, locks or changes space, not on device lock (decided 2026-11-01);
- 22, an edit rewrites the contact's row in place, under the same ID, in place of "append a new row, shred the
  old", so the table grows only with contacts ever added, plus noise (decided 2026-11-01);
- 20, every contact gets a random 16-byte ID at creation (at migration for existing ones), held only inside its
  sealed record and in rows sealed under the same space key; the address-book ID is used once at import and never
  stored (decided 2026-11-02);
- 21's remainder: one table and one row size, about 8 KB, for every small space-sealed record (contacts, groups,
  backup keys, custody shards, the shard and restore queues), its type inside the seal, so item 21's one noise
  draw covers them all and there is no size spread to match; photos and vault entries stay out (decided
  2026-11-02);
- photos: their own table, one row per photo of one fixed size, about 24 KB, re-encoded at about 360 px with its
  metadata stripped, the original not kept, and no noise rows (decided 2026-11-02; the leak this leaves is open);
- vault entries: their own table, 4 KB rows with notes limited to about 3.5 KB of text, and a noise count drawn per
  install uniformly from 10–200, never stored, written when the contact noise is (decided 2026-11-02);
- 26, a store-layer test that old ciphertext is gone from the file and its `-wal` after a write and a checkpoint,
  and the store closed when the app goes to the background so SQLite deletes the `-wal` instead of truncating it,
  with a test that it is gone (decided 2026-11-02);
- 27's grace period: 5 minutes in the background, as today, at every depth, through a copy of the space key in
  memory wrapped by a per-session Enclave key that works only while the phone is unlocked (decided 2026-11-02);
- 6, a spare iPhone with no real data, ideally an iPhone 11, for stage 3 on, and until it arrives a measuring app
  with its own bundle ID for the device timings (decided 2026-11-02; neither exists yet);
- the spec's 2026-10-15 sub-items: one salt and one Enclave key per install (forced by §1.5), and PBKDF2-HMAC-SHA256
  through CommonCrypto, not Argon2id, tuned to about 1 s on an iPhone 11; the rest were superseded or decided
  above (decided 2026-11-02);
- the data slices ship together, in one reseal (§7.1);
- Bug 120 is recorded as a stated limit: a duress space protects against one image, not a series; what is fixed
  in one image is uniform records, sizes and no space tag (§5; it stays open in the register).

**Open, needs a decision:**
- spec §2 still describes the 2026-10-15 storage design as history and needs rewriting for independent spaces
  (its open sub-items were closed 2026-11-02);
- the photo table has no noise: right after migration, a photo row the open space can't read proves another space
  (§1.5);
- the unlock cost, to be measured on a device, by the measuring app of decision 6 (PR #155; not run on a device);
- 26's remainder: stale copies of the main store file's pages in APFS free blocks and flash, readable with a raw
  image, the file's key and the phrase;
- 29, found while writing the migration tests (§3.3): whether copies of a contact that several depths show share
  one ID and its prekey state, and what happens to a contact record or a vault note too large for its row;
- 30, one person paired in two spaces: both spaces match the sender, and a long-term message without ML-KEM
  opens in both; the owner proposed an ID per pairing (2026-11-03);

**What this is.** A plan for shipping the diceware phrase that replaces the PIN. It covers four areas:
- how the phrase is typed and learned;
- how installs with a PIN migrate;
- how data moves from the local DB key to phrase-derived depth keys;
- how multiple depths work under phrases.

**Where it sits.** [`PASSPHRASE_LAYER_KEYS.md`](../../Occulta/Features/SecureMode/PASSPHRASE_LAYER_KEYS.md)
owns the cryptographic design. [ROLLOUT_PLAN.md](ROLLOUT_PLAN.md) owns the sequencing of the whole hardening
plan. This document is a proposed refinement of that plan's stages 2–4 for the phrase alone.

**What it builds on.** The spec's design discussion of 2026-10-15, all of it open there. This document doesn't
restate it:
- one salt and one Enclave key per install (§1);
- storage for per-depth keys: depth keys from phrases, a chain between depths, a shared key, origin lists,
  and requirements 1–7 (§2);
- the finding that the write-frequency requirement can't be met against a surrendered phrase (§2);
- 7 words with PBKDF2 through CommonCrypto (§4);
- holding the key until the device locks (§4).

It also builds on the 2026-10-16 decisions (`bugs.md` Bug 168): the prekey refactor ships in 2.0.0 without
waiting for this work, and a downgrade must lose nothing, through a new store file (proposed then).
*2026-10-29:* the reseal writes a new store file, but a downgrade after migration is not supported (decision 18).

**What is new here.**
- Phrase entry and learning (§2).
- Each starting state's migration (§3), and the tests that prove it loses nothing (§3.3).
- Rule 4's way back (§1.2).
- The coercion gate under phrases (§1.3).
- Installs with no lock (§1.4).
- Key slots, considered and not adopted (§1.1).
- Stages and effort (§7).

Code references are against `75e86c39`.

---

## 1. Proposals and findings

### 1.1 Key slots: not adopted

**Decided 2026-10-19 by the owner: direct derivation.** Rows are sealed directly under `layerKey_D`, as the spec
has it, and key slots are not adopted. Release order B (§7.1) drops out with them. The comparison below is kept
as the record (`decisions.md`, 2026-10-19).

**The 2026-10-15 design.** A depth's header slot holds the canary, the key of the depth below it, and the
shared key. Rows are sealed under `layerKey_D` itself.

**Key slots.** The header slot would also hold a random depth key, and rows would be sealed under that key.
The chain would carry the random keys.

**What it buys.**
- **A later change to the derivation rewraps a slot.** Adding the Enclave step later, raising the PBKDF2
  count or changing the KDF no longer reseals every row. Older images keep the old slot, which is as strong
  as the phrase under the old derivation.
- **A device slot.** A depth key wrapped under an Enclave key that needs only an unlocked device. It gives
  installs with no lock (§1.4) and a lowered gate (§1.3) the same storage as everyone else. Direct derivation
  can do the same with a phrase-less derivation, so this is a convenience, not a capability.
- **A silent reseal before any phrase exists.** Every install reseals under device slots, and phrases come
  later.

**What it doesn't buy.** The first draft of this document overstated these:
- **Earlier images can still unwrap a device slot.** A device slot is on disk in every image taken while it
  exists. If the depth key later moves to phrase-only, those images can still unwrap it, through the old
  Enclave key's copy in the image. Moves to phrase-only include turning a lock on, raising a lowered gate,
  and graduation after a silent reseal.
  - Nothing documents that deleting an Enclave key revokes an older copy (Prekey Continuity §9, D9).
  - The rows stay under the same key, so those images also open data written later.
  - Only a rekey cuts them off, and a rekey is a reseal.
- **So the silent reseal costs a second reseal at graduation.** That is the cost Rule 1 exists to avoid.
- **Regenerating an exposed phrase needs a reseal either way.** Rewrapping protects only if no image was taken
  while the old slot existed, which can't be known.

**Without the silent reseal, what remains is the first point:** changing the derivation later without a
reseal. **Open, needs a decision.**

### 1.2 Rule 4's way back: the old store file

**Superseded 2026-10-29 by the owner: no probation week.** The setup ladder (§2.5) is the only check that a phrase
is remembered. The reseal still writes a new store file, and the old store stays until the reseal has been
verified. Then it is deleted, with its keys, as for an install with no lock (§1.4). The old PIN is no longer a way
back, so a phrase forgotten after setup loses that space's data for good. Why it was dropped: the old store sits
on disk as exposed as today's data for the whole week, tracking progress needs a record per space (decision D),
and no mainstream app holds old data for days pending proof of recall. What remains of this section is the record
of the earlier design. The deletion list in §3.2 still applies, at the end of the reseal instead of at graduation.

**Decided 2026-10-19 by the owner: adopted as proposed below,** both the new store file and the old store as
the way back (`decisions.md`, 2026-10-19). ~~Still open: what a newer build does with a store an older build wrote
to in the meantime (ROLLOUT_PLAN, "A downgrade loses nothing").~~ **Decided 2026-10-29 (decision 18):** a downgrade
after migration is not supported.

Rule 4 keeps a way back until every phrase is proven. The migration requirement of 2026-10-16 proposes
writing the migrated data to a new store file and removing the old store only after the switch (ROLLOUT_PLAN,
"A downgrade loses nothing"). That old store can be the way back, with no new key escrowed anywhere.

**How the week runs.**
- **The reseal runs at phrase setup,** into the new store, sealed under phrase-derived keys only.
- **The old store stays untouched until graduation,** with its keys (the local DB Enclave key and the keychain
  random) and the PIN verifiers inside it.
- **A forgotten phrase during the week:** the old PIN opens the old store as it was at setup. Changes made
  since are lost, and the screen must say so.
- **An image taken during the week** holds two stores:
  - the old one, which shows data as of setup and is readable with the passcode, as all data is today;
  - the new one, which needs the phrases.
- **Graduation** deletes the old store, its keys and the Secure Mode PIN key together.

**Costs.**
- A phrase forgotten during the week loses that week's changes.
- Two stores sit on disk for a week.
- The old store stays as exposed as today's data until graduation.

**Compared with device slots (§1.1),** this leaves nothing that opens the new store once graduation is done.
~~**Open, needs a decision.**~~ **Decided 2026-10-19, superseded 2026-10-29** (top of this section).

### 1.3 The coercion gate under phrases

Today the user chooses the PIN. Two coercion paths depend on that, and so does an absolute depth number.

**Decided 2026-10-19 by the owner (7a–7d; `decisions.md`, 2026-10-19).** The governing rule, raised by the owner:
lock off and lock on must behave identically at every depth and on every install, Secure Mode or not. That
covers the screens, the time taken, what Settings shows afterwards and what changes on disk. Any difference
identifies duress.
- **7a, lock off: kept, built one way for everyone.** Lock off stores the current depth's key under a
  device-only key, so the app opens without a phrase.
  - On an install without Secure Mode, that depth is depth 0. At a duress depth, it is that depth.
  - The container for that key exists on every install, filled with random bytes when no depth has its lock
    off, so its presence says nothing.
  - Images taken while a depth's lock is off can open that depth until it is resealed.
- **7b, the real depth: refused while duress depths exist.** To go lock-free, the real user removes Secure Mode
  first. A coercer is never at the real depth without its phrase, so the refusal is never observed.
- **7c, lock on in a decoy: a new depth below it.** A new phrase means a new key, which the parent's chain copy
  can't follow. Requirement: it takes the same steps and time, and shows the same contacts, as an ordinary
  install's lock-on, which reseals depth 0 under the new phrase. ~~How is design work, open, needs a
  decision.~~ *Superseded 2026-10-29: no new depth (below).* The real user doesn't need this flow to accept an existing phrase: once the lock is on, the lock
  screen does that.
- **7d:** below, under "Depths a coercer created".

**Decided 2026-10-29 by the owner for independent spaces (7b); 7c and 7d follow from it and from §1.5.**
- **7a stands.** Lock-off is built one way for everyone.
- **7b: the refusal is dropped.** The app keeps no list of spaces, so it can't know whether duress spaces exist.
  Lock-off is allowed in every space and on every install, with one warning, the same everywhere: anyone who
  unlocks this phone will open this data. The space's key goes under the device-only key. While the lock is off no
  phrase is asked, so the user's other spaces can't be opened until the lock is turned on again.
- **7c: no new depth.** Lock-on reseals the current space under a new phrase, exactly as an ordinary install's
  lock-on does, so there is nothing to make identical.
- **7d: migration only.** The old store's PIN list and `coercerBaseDepth` still name coercer-created layers, so
  they are dropped at setup with the contacts they created. After migration a coercer-created space is just
  another space, which the app can't list or drop.

The reasoning before the decision follows.

**The absolute depth number goes regardless.** Requirement 1 of the 2026-10-15 storage drops absolute depth
numbers: the persisted `currentDepth`, `coercerBaseDepth` and the verifier indices. The logic from Bugs 37,
58 and 61 is built on those, so it is rewritten whatever is decided here.

**Lowering the gate** (`disablePIN(at:confirmingPIN:)`,
[Manager+Security.swift:857](../../Occulta/Features/SecureMode/Manager+Security.swift)) opens the app at a
depth with no PIN.
- Under phrases, that depth's key has to open without its phrase. So it is stored under a device-only key, in
  either design.
- Raising the gate again leaves earlier images able to open that depth (§1.1).
- At a duress depth that may be acceptable. At the real depth it hands the real key to anyone with the
  passcode.
- The two options both have a cost. Warning the user leaves the protection in place but exposed. Allowing
  the switch only at duress depths makes the depths behave differently.

~~**Open, needs a decision.**~~ **Decided 2026-10-19 (7a, 7b), and 7b changed 2026-10-29** (above).

**Re-enabling the gate** (`reEnablePIN`,
[Manager+Security.swift:898](../../Occulta/Features/SecureMode/Manager+Security.swift)). The Bug 37 fix accepts
an unknown PIN at depth > 0 as a new layer. That keeps re-enabling indistinguishable from a first-time setup.
Phrases are generated by the app, so the flow can't be carried over as is.
- A first-time lock setup shows a new phrase. A real user returning to an existing depth needs to type their
  existing phrase in a flow that looks the same.
- One candidate: the confirmation step accepts either the phrase just shown (a new layer) or any existing
  phrase (route there).
- Its catch: anyone watching sees the user type something other than what the screen showed.

**Open, needs a decision.**

**Depths a coercer created** through that path. The real user doesn't know their PINs, yet Rule 2 needs every
depth's phrase in one sitting. **Decided 2026-10-19 by the owner (7d): dropped at phrase setup** (§3.1), as
`forceDeactivateForRecovery` drops every layer today:
- **The contacts those depths created go with them,** as deletions (orphan-in-place). Under the 2026-10-15
  storage, a contact created at a duress depth stays hidden from the depths above only through that depth's
  origin list. Dropping the list without the contacts would put them in the real user's contact list.
- **A returning coercer** finds their PIN dead, as everyone's is after the release. ~~During the probation week
  the old store still opens with it, as it was at setup.~~ *Superseded 2026-10-29: no probation week (§1.2).*
- `decisions.md`, 2026-10-19.


### 1.4 Installs with no lock

**Decided 2026-10-19 by the owner: option 2, migrate everyone** (`decisions.md`, 2026-10-19).
- Depth 0's key is derived from an empty phrase, with the install's salt and Enclave key. Protection stays at
  today's level.
- With no phrase to forget, there is no probation week. The old store and its keys are deleted once the reseal
  checks out.
- Turning a lock on later reseals depth 0 through the same path.

The 2026-10-15 storage doesn't say what an install with no app lock does. Two options:

1. **It stays on today's store and key until a lock is turned on,** which runs the migration then. The code
   keeps two formats for as long as such installs exist.
2. **It migrates too,** with depth 0's key derived without a phrase (a fixed empty input). The code has one
   format. Turning a lock on later reseals depth 0.

Either way:
- an install with no lock keeps today's protection;
- whether an install has a lock stays visible, as it is today through `sealedNormalVerifier`.

~~**Open, needs a decision.**~~ **Decided 2026-10-19: option 2** (above).

### 1.5 Independent spaces

**Decided 2026-10-29 by the owner, from the brainstorm of 2026-10-27 to 29** (`decisions.md`, 2026-10-29). This
replaces the 2026-10-15 storage design (header slots with a canary, the chain, the shared key, origin lists).
Decision 1 is closed by it.

- **A space is a key plus whatever rows decrypt under it.** No shared keys, no pointers between spaces, no depth
  numbers. A valid phrase that decrypts nothing is a new, empty space.
- **Phrases are generated by the app, 7 words, never chosen** (decision 12).
- **An empty duress space is acceptable.** The cover story is "I deleted everything", which needs deletion to
  look the same as another space's rows and as noise (below).
- **No canary record, and no record that only spaces have.** A per-space record is countable once its format is
  known, and the format is public.
- **No common pool.** No row is readable without a phrase or shared by all spaces. A coercer who types any
  phrase and sees common rows can subtract them from the duress view, and an empty difference exposes the decoy.
  A fresh phrase opens nothing, on every install.
- **The passphrase stays optional** (decision 5). An install with no lock migrates under an empty phrase, which
  has to bypass any phrase-format check.
- **No per-space identity key** (15b). The identity stays in the keychain.
- **KDF input is the word indices**, not text, so case, Unicode and the four hyphenated words never enter it.
- **Deletion crypto-shreds.** A deleted row is overwritten with random bytes and kept, so deleted rows, other
  spaces' rows and noise look the same. The deletion marker moves inside the sealed payload; `Contact+Model.swift`
  keeps `deletionToken` in a plain optional field that queries filter on (`:106`, `:405`), so its nil or non-nil
  state is readable without a key. The soft-delete cap of 50 rows has to go with it.
- **No slot-indexed verifier arrays.** Today `sealedNormalVerifiers[0]` is always the master PIN and duress PINs
  match at N ≥ 1 (`AppLayerConfig+Model.swift:117-123`), so a duress holder learns that an index 0 exists.
- **No per-row key header** (decided 2026-10-29, replacing the brainstorm's proposal). Unlock trial-decrypts the
  contact and group records whole. They are text-only sealed records of a few KB, so 10k of them is tens of MB,
  which hardware AES-GCM reads in tens of milliseconds (an estimate, to be measured on a device). It isn't the
  per-row-key variant the 2026-10-15 design rejected either, since there is no row key.
  - **Photos live in their own table,** one sealed row per photo. The link is not a column: the sealed contact
    record lists its photos' row IDs, and a photo row names nothing. A contact can have none, one or two
    *(2026-11-02: none or one)*. Unlock
    never reads photos; they are fetched by ID once the contact opens. A retired photo is shredded like any
    deleted row. The table shows how many photo rows exist, not whose or which are active. ~~It needs noise rows
    in the same size buckets, and photos stored at bounded sizes, or the total would track the real photos of
    every space. The bucket sizes are open, needs a decision.~~ **Decided 2026-11-02 by the owner:** one fixed
    size, about 24 KB. A photo is re-encoded at import to about 360 px (3× a 120-pt avatar) with its metadata
    stripped, its quality lowered until it fits, and the original isn't kept; the thumbnail is made from it in
    memory. **No noise rows.** *Open, needs a decision:* right after migration the table holds exactly every
    space's photos, so a photo row that no contact in the open space lists proves another space. Deleted and
    replaced photos give cover only once the user has made some. The count also tracks every space's photos
    together.
  - **Vault entries keep their wrapped entry key** (`VaultEntry.encryptedEntryKey`), which is a cheap check of
    its own, so they need no new header. **Decided 2026-11-02:** their own table, 4 KB rows (an entry is text
    only: a seed phrase, a note or a key token, with notes limited to about 3.5 KB of text), and noise rows drawn
    per install uniformly from 10–200, never stored, written at the same moments as the contact noise (§8, 21).
    A hidden space of 40 entries stays unprovable on 79% of installs. At the cap the noise is about 0.8 MB.
  - **Fallback:** a 16-byte locator tag per row (an HMAC under a subkey of the space key), if a device
    measurement shows unlock is too slow.
- **Removing a space:** unlock it, crypto-shred its rows into noise, and forget the phrase. The app keeps no record
  of the space.
- **Cost accepted:** a decoy goes stale unless it is actually used. Nothing copies the real space's changes into
  it.

- **No typo check: no checksum in the phrase, no retype before the first write** (decided 2026-10-29, item H of the
  brainstorm dropped). A mistyped phrase opens an empty space, and the app can't tell it from a new one. Anything
  written there is reachable only by typing the same typo again. Phrase strength stays 7 words, 90.5 bits.

- **A bundle for a contact in another space** (decided 2026-10-29): the app ignores a bundle whose blinded
  `senderFingerprint` matches no contact in the open space, with the same screen, wording and timing as for a
  corrupt or misaddressed file. It reveals nothing about another space, and the file opens when the right space is
  open. No notice is shown, since a notice would name a contact the open space can't see. ~~Open, needs a
  decision (2026-10-31): a known person's file that won't open is the rejection oracle `b1f9045` removed (§8, 24).~~
  **Decided 2026-10-31:** the screen says "The contact who sent this message was deleted or cannot be found", the
  same as for a deleted contact, so "I deleted them" covers it (§8, 24). *2026-11-03:* this assumes one space
  matches the sender. One person paired in two spaces matches both (§8, 30).

~~**Proposed in the brainstorm, not decided:** uniform records and noise rows (Bug 120).~~ **Decided 2026-10-29**
(§5, Bug 120): one sealed record per contact in one table, a few fixed sizes with noise rows in the same sizes, no
space tag, and ~~every change written as "append a new row, shred the old"~~ *(2026-11-01: an edit rewrites the
row in place, §8, 22)*. ~~Open, needs a decision: how many noise
rows there are, and a table that only grows (§8, 21 and 22).~~ **Decided 2026-11-01:** the contact table's noise
count is drawn per install, uniformly from 50–1,000, and never stored (§8, 21). ~~Open, needs a decision: a table
that only grows (§8, 22),~~ **Decided 2026-11-01:** an edit rewrites the row in place, so the table grows only with
contacts added (§8, 22). ~~Open, needs a decision: the noise for the other space-sealed tables (§8, 21).~~
**Decided 2026-11-02:** one table and one row size for every small space-sealed record, so the contact noise
covers them all (§8, 21); the "few fixed sizes" above become one.

**Unverified estimates:** unlock is about 1 s of KDF, 50–200 ms to fetch 10k rows and 10–20 ms to trial-decrypt
10k small headers. Not measured on a device.

**Measured 2026-11-01 on an iPhone 15 Pro, iOS 26.7.1** (`ContactRecordCryptoMeasurementTests`, mock 8,220-byte
records, crypto and encoding only, no store read; median of 5 passes):

| Records | Derive the space key (Enclave ECDH, ML-KEM, HKDF) | Reject 1,000 noise rows | Open all | Seal all | Total |
|---|---|---|---|---|---|
| 100 | 6.8 ms | 3.6 ms | 3.8 ms | 3.4 ms | 18 ms |
| 1,000 | 6.8 ms | 3.7 ms | 37 ms | 33 ms | 82 ms |
| 5,000 | 13 ms | 3.7 ms | 183 ms | 166 ms | 370 ms |

- One Enclave ECDH costs about 4.6 ms here against 0.23 ms on the Simulator, so one per record would cost 4.6 s at
  1,000 records. The design's one derivation per unlock stays.
- Opening is mostly JSON decoding: a noise row fails its tag check in under 4 µs.
- Still unmeasured: PBKDF2, reading the rows from the store, and an iPhone 11 (decision 6).

### 1.6 Binding each sealed record to its row (step 5)

**The requirement is decided** (2026-09-26, `bugs.md` Bug 123; spec §2, requirement 6): every sealed blob is bound
to its row with an AAD built from the row's ID. **How it applies under independent spaces is proposed 2026-11-02,
not decided.**

**What happens to the fields Bug 123 named.** Each one was sealed on its own with one fixed AAD byte, so a value
copied from one row to another opened cleanly. Under §1.5 and §8, 21 none stays a field of its own:

| Field | Today | Under spaces |
|---|---|---|
| `Contact.Profile.originDepth`, `.visibleThroughDepth`; `VaultEntry.visibleThroughDepth`; `BackupEncryptionKey.depth` | Depth stamps | Dropped (requirement 1): the key that opens a row is its space |
| `Contact.Profile.globalTrusteeDepth` | Always an encrypted −1 since Global Trustees retired; nothing reads it | Dropped; already due to leave the schema |
| `deletionToken` on `Contact.Profile`, `VaultEntry`, `BackupEncryptionKey`, `PendingShamirSecretRestore` | A sealed sentinel; the contact's is a plain optional that queries filter on | Inside the record's seal; a deletion crypto-shreds the row (§1.5) |
| `PendingShamirSecretRestore.attributeID` | Sealed on its own | Inside the record's seal, in the small-record table (§8, 21) |

So step 5 becomes binding whole records, not fields. Each row of the new store is a random 16-byte ID and one
sealed record (§8, 23); a vault entry's row holds two seals, its wrapped entry key and its content.

**Construction.**
- **AAD = a table label ‖ the row's 16-byte ID**, plus a field tag only where a row holds more than one seal (a
  vault entry's key and content, as `VaultEntry.aad(for:)` does today).
- **The label** is a constant per table: small records, photos, vault entries. It is never stored, so it leaves
  nothing in the file, and it makes a record moved between tables fail whatever the row sizes are.
- **Not in it:**
  - the record's type, which is inside the seal (§8, 21); unlock doesn't know it before opening;
  - a creation date, since the new store has no plaintext column to take it from (today's `VaultEntry.aad(for:)`
    uses `createdAt`);
  - any space identifier, since none exists, and another space's key already fails.
- **In the store layer, not at call sites.** Stage 0's store layer seals and opens only through calls that take the
  table and the row ID, so no caller can seal without them. The binding then costs nothing extra in stage 3 or 4.
- **The layout is a sealed contract,** like `Message.Draft.aad(for:)`: changing it makes every row unreadable. Pin
  it with a test vector.

**What it gains.** Within one space, a record copied onto another row fails to open and reads as noise. Without it,
the copy opens as that row:
- a photo copied onto another contact's photo row shows on the wrong contact;
- a contact's record copied onto a noise row makes a second live copy, so deleting the contact leaves one behind.

It costs no stored bytes and no measurable time, since the row ID is read with the row.

**What it doesn't stop.**
- Anyone holding the space's key, who can seal anything they like. Nothing binds against that.
- **Rolling a row back to an older version of itself. Open, needs a decision.** An edit rewrites a row in place
  under the same ID (§8, 22), so an older ciphertext of that row from an earlier image still opens (§8, 26).
  Someone who can write the store can bring back a deleted contact's record, or a contact's earlier keys. Closing
  it needs something per space that changes with every write, which §1.5's "no per-space record" rules out (§8,
  28).

**Tests, before stage 3 counts as done:**
- A record copied from one row to another in the same table and space fails, and unlock skips it exactly as it
  skips noise: same path, no separate error.
- Two photo rows' ciphertexts swapped: both fail, and neither contact shows the other's photo.
- A record moved into another table fails, from the label.
- A vault entry's wrapped key or content swapped with another entry's fails (true today; carried over).
- Every migrated record opens under its new row ID, as part of C3's "data survives" test.
- The AAD layout matches its pinned vector.

**Still to sweep (stage 2):**
- sealed fields that stay in SwiftData's install-wide state;
- drafts, which hold contact references sealed under the space key (§8, 20) but have no table assigned yet. Today
  they bind to their row ID and a field tag (`Message.Draft.aad(for:)`).

Each gets the same rule.

---

## 2. Typing the phrase

### 2.1 What the wordlist allows

Measured 2026-10-19 on the bundled `Assets/eff_large_wordlist.txt`:

| Measure | Value |
|---|---|
| Words | 7,776; letters a–z, plus 4 hyphenated: `drop-down`, `felt-tip`, `t-shirt`, `yo-yo` |
| Words that are the start of another word | None |
| Letters until a word is unique | Mean 5.29; 59% within 5 |
| Words sharing a given word's first 3 letters | Median 12, mean 18, max 85 |
| Taps per word, typing until unique | 5.29 (37 per phrase) |
| Taps per word, typing with a 4-word suggestion bar from the 3rd letter | 4.83 (34 per phrase) |
| A 6-digit PIN | 6 |

Because no word is the start of another, a word can commit itself as soon as its prefix is unique, with no
confirm step.

### 2.2 Keyboard

**Design, with the decisions of 2026-10-19 (12, 13a, 13b; `decisions.md`).**
- **Keys.** In-app letter keys. Letters that can't continue any list word are disabled, so a typo can't
  happen.
- **Completion.** A word commits when its prefix is unique, about 5.3 letters on average, so 37 taps for 7
  words.
- **No suggestion bar** (13a). It would save about 3 taps a phrase, and it puts whole words on screen, which are
  easier to read from a distance or on CCTV than taps on keys.
- **No visual feedback on a tap,** haptics only. Committed words show as dots, with press-and-hold to show them.
- **What it can't stop.** A camera that can see the keys still sees which keys are tapped. So the setup screen
  tells the user to shield the screen while typing, which belongs in step 16's guidance.
- **VoiceOver** (13b) behaves as it does in iOS's own password fields. The setup screen suggests headphones to
  VoiceOver users, because keys are read aloud as they are touched.

**Why not the system keyboard.** Nothing reaches the keyboard's learned words, and there is no paste, no
dictation and no third-party keyboard. Spec §4 requires this whichever way the rest is settled.

**Snapshots and state restoration.** The phrase stays out of both. `AppScreen` already covers the
app-switcher snapshot.

### 2.3 Generator

Generation needs four changes. `Manager.PassphraseGenerator.generate` defaults to 5 words, and its
`% 7776` has a tiny bias: 2³² mod 7776 = 2560, so the first 2,560 words are very slightly more likely.

- **7 words**, per spec §4.
- **Rejection sampling** in place of the modulo.
- **Skip the 4 hyphenated words**, so the keyboard needs letters only. That costs 0.0007 bits per word.
- **A separate function.** `generate(sharedKey:)` produces the key-exchange comparison words. Those must stay
  byte-identical, or an older peer shows different words.

### 2.4 Option: a list with unique short prefixes

The generator could draw from a subset in which every word is fixed by its first few letters:

| Subset | Words | Bits per word | Words for ≥ 90 bits | Taps per phrase |
|---|---|---|---|---|
| Full list | 7,776 | 12.92 | 7 (90.5 bits) | 34–37 |
| One word per 4-letter prefix | 3,748 | 11.87 | 8 (95.0 bits) | 32 |
| One word per 3-letter prefix | 1,375 | 10.43 | 9 (93.8 bits) | 27 |

With a subset, entry can be fully blind: no suggestion bar, nothing on screen but dots. The tradeoff is one
or two more words to memorise. Spec §4's word count assumes the full list; a subset changes the count, not the
strength target.

**Decided 2026-10-19 by the owner (decision 12): the full list, 7 words** (`decisions.md`, 2026-10-19). Fewest
words to memorise. The cost is the suggestion bar of §2.2, which shows candidate words on screen as they are
typed (decision 13).

### 2.5 Learning, and where gamification fits

Memorising is the real burden, more than typing: 7 random words per depth, so 21 for someone with two duress
layers. Gamification goes there.

- **Setup ladder.** See the phrase → fill 2 gaps, choosing from 4 words → put the shuffled words in order →
  type it unaided. Each step must pass before the next.
- **Probation progress.** Rule 4 becomes a ring that fills with correct entries spread over several days.
  When it completes, the app graduates (§3.2).
- **Rehearse: not built (decided 2026-10-29, superseding decision 14).** Routine use already makes users type the
  real phrase, since the key is held only until the device locks (spec §4). A duress phrase is typed rarely, and
  forgetting it loses only decoy content, which an empty duress space already accepts. No prompt, no Settings
  entry and no stored date. The text below is the earlier design.
- **Rehearse.** At the real depth, check any depth's phrase without changing depth. It counts toward that
  depth's Rule 4 progress. After graduation, duress phrases are rarely typed. A periodic rehearsal prompt
  would need a stored "last rehearsed" per depth. **Decided 2026-10-19 by the owner (decision 14):**
  - **A prompt about monthly at unlock,** with "Later", plus "Rehearse phrases" in Settings.
  - **What it covers.** Each depth prompts for the phrases of the depths below it. A depth with nothing below it
    never prompts, like an install without Secure Mode.
  - **What it stores.** The last-rehearsed date is one ordinary row in the general pool, sealed under that depth's
    key (requirements 1 and 7).
  - `decisions.md`, 2026-10-19.

**Constraints.**
- No notifications or badges; `OSTraceTests` forbids them.
- The only stored state is the Rule 4 progress. Per the 2026-10-15 requirements:
  - it lives in rows in the general pool, sealed under each depth's key (requirement 7), not in a
    32-entry array where only real entries change;
  - it names no absolute depth (requirement 1).
- The screens are the same at every depth. A duress depth shows only its own phrase's progress.
- Every lock user gets them (Rule 3).

**Decided 2026-10-19 (13a, 13b; §2.2):** no suggestion bar, and VoiceOver as in iOS's password fields, with a
headphones suggestion.

---

## 3. Migrating installs that have a PIN

### 3.1 Starting states

Assuming §1.2: the reseal happens at phrase setup, into a new store.

| Today | At phrase setup | Notes |
|---|---|---|
| No lock | The reseal, with depth 0's key from an empty phrase; no probation week | The old store and its keys go once the reseal checks out (§1.4) |
| PIN only | 1 phrase; the reseal into the new store | ~~The old store stays until graduation~~ The old store goes once the reseal is verified (2026-10-29, §3.2) |
| Secure Mode with K duress layers | At the real depth, after the master PIN: K+1 phrases in one sitting (Rule 2), then one reseal of every depth | Only the real user can give every phrase |
| Unlocked at duress depth N | The same prompt as everywhere. Setup there sets up that depth for real: its phrase, and the data it can see, in the new store. The real user finishes the other depths later from the real depth, typing the decoy's phrase again | **Decided 2026-10-19** (8a, below) |
| Gate lowered at depth N | Behaves like an install with no lock: silent migration, no prompt, the depth's key under a device-only key (7a). The real user gets back by turning the lock on (7c) and using the lock screen, then finishes setup | **Decided 2026-10-19** (8b, below) |
| Depths a coercer created (`coercerBaseDepth > 0`) | Dropped at setup, as `forceDeactivateForRecovery` does today, together with the contacts they created | **Decided 2026-10-19** (§1.3) |

**Decided 2026-10-19 by the owner (8a, 8b; `decisions.md`, 2026-10-19).**
- **8a. A setup started in a decoy is real for that decoy.** Its phrase is set, and the data it can see moves
  into the new store, under its key and the shared key.
  - The real user finishes the other depths later, from the real depth, typing the decoy's phrase again. Rule 2
    holds from then on.
  - The exception to Rule 2 is visible only by comparing images over time, the leak the spec already lists as
    open (Bug 120).
  - Until the real user finishes, the old store opens with the passcode, as all data does today. So the window
    is no weaker than today.
  - **Changed 2026-10-29 (no probation week, §1.2):** the old store and its keys are deleted only once every layer
    in its PIN list has migrated, not when a single reseal verifies. This is a state of the migration alone and
    nothing of it is kept in the new store. 8b follows the same rule: a layer with its lock off migrates silently,
    and the old store waits for the others. Rule 2 stands for the migration: the real user sets up every layer's
    phrase in one sitting.
- **8b. A decoy with its lock off behaves like an install with no lock.** It migrates silently, with no prompt,
  and its key stays under a device-only key (7a).
  - The real user gets back by turning the lock on (7c) and typing the real phrase or PIN at the lock screen,
    then finishes setup.
  - ~~The depth 7c creates on the way is removed later (decision 9).~~ *Superseded 2026-10-29: 7c creates no
    depth, and there is no remove action (§1.3, decision 9).*

### 3.2 Probation and graduation

**Superseded 2026-10-29: there is no probation or graduation.** The deletion below runs when the reseal has been
verified, with the same caveat for tier U's `r_U` and ML-KEM record. The "use my old PIN" option and the Rule 4
progress ring (§2.5) are not built. What a forgotten phrase costs is stated in the setup copy, which is the only
safeguard besides the ladder. Decision 10 (setup required at the first unlock) stands.

**During probation.** Until graduation, the lock screen asks for the phrase. Every lock user also gets
"use my old PIN", which opens the old store as it was at setup (§1.2).

**Graduation.** When every phrase is proven, these are deleted together:
- the old store;
- the local DB Enclave key (`local.db.se.key.occulta`), which leaves every copy of the old store unreadable.
  - *Corrected 2026-10-24 for Bug 171's fix (#123):* tier U's Keychain secret `r_U` (`local.db.random.key.occulta`)
    and, on iOS 26+, its ML-KEM record (`local.db.pq.key.occulta`) also key shard custody, the restore buffer, the
    PIN-verifier wrap and compose staging.
  - So they go only once nothing else uses tier U (ROLLOUT_PLAN stage 4).
- the Secure Mode PIN Enclave key (`app.layer.key.occulta.v1`).

**What the deletion shows.** Keychain items carry creation dates, and an item's absence is visible. Since every
install migrates (§1.4), every install loses the old keys: at once with no lock, at graduation with one. Their
absence says only that the install has migrated. The deletion's date can still differ by about a week between
the two, which says no more than today's verifier scalar about whether there is a lock.

**Setup deadline. Decided 2026-10-19 by the owner (decision 10): required at the first unlock after the update,**
with no "Later" (`decisions.md`, 2026-10-19).
- There is no opt-in period, so setting up early marks no one (Rule 3).
- After the update, no install keeps the PIN path ~~beyond the probation week~~ once its reseal is verified
  (2026-10-29: no probation week).
- The cost: after the update, a lock user can't use the app until setup and its learning steps are done, even
  at a bad moment.
- A decoy is no different (8a).

### 3.3 Migration tests

**Added 2026-11-03 at the owner's request.** These tests prove that moving from today's encryption to phrase-derived
space keys loses nothing, with the lock on and with it off, on mock data. They are register C3's "data survives"
test (TEST-2) for this migration. No slice counts as done until its part passes (§6).

**The mock data: today's store, sealed the way today's app seals it.** Build on Bug 171's frozen fixture
(`LegacyStore` in `OccultaTests/SecureMode/KeyResealFixtures.swift`). It already seals a value for every encrypted
field under fixed `TestKeyManager` keys, in both key forms (`KeyForm`: below iOS 26 and iOS 26+), with byte values
checked against recorded ones. It needs the following added:
- **Several depths, with data at each.** That means contacts in every visibility class:
  - visible everywhere;
  - visible through depth N;
  - hidden at every duress depth;
  - created under coercion at depth N (`originDepth`);
  - soft-deleted.
- **Vault entries** at each depth, plus one that is unclassified.
- **Groups** whose members span those classes, **drafts** addressed to them, **backup keys**, **custody shards**,
  **restore records** and the **queue records** listed in §8, 21.
- **Every field filled.** Each contact also has a prekey record, and one has a photo.
- **Edge cases:**
  - empty strings;
  - a contact record larger than its 8 KB row;
  - a vault note longer than about 3.5 KB;
  - a photo larger than 24 KB.

  What the migration does with the three that don't fit is open, needs a decision (§8, 29).
- **What each depth shows, spelled out in the fixture as literal lists.** A fixture guard checks that today's code
  (`Contact.Profile.isVisible(atDepth:)`, `VaultEntry.isVisible(atDepth:whenUnclassified:)` and the group and
  backup-key filters) agrees with those lists. A later change to today's filters then can't quietly move what the
  tests expect.

**What every test checks.**
1. **Each space shows exactly what its depth showed.** After migration, opening each space with its phrase shows
   the same records as the literal list for that depth, with the same plaintext, compared field by field. Nothing
   may be missing and nothing extra may appear.
   - Photos are compared by what the re-encoding promises (§1.5): the photo decodes, is about 360 px, carries no
     metadata, and belongs to the same contact. The original isn't kept, by decision.
2. **References resolve within the space.** Every group member, draft recipient, custody and shard payload and
   `TrusteeTag` in a space names a contact in that same space: the one it named before, now by its random ID (§8,
   20). No reference holds the old identifier's ciphertext, and no reference holds an address-book ID.
3. **Prekeys survive.** A message sealed to a contact's prekey before the migration opens after it, in the space
   that holds the contact (ROLLOUT_PLAN, "Prekeys survive the retagging").
4. **Nothing opens anywhere else.** No record opens under another space's key, and a fresh phrase opens nothing.
   Noise rows open under no key. Each record is bound to its row (§1.6). The new store's row count equals the
   records of every space plus a noise count inside the decided range.
5. **The old store isn't touched until every layer has been migrated and verified.** Before that, it is
   byte-for-byte what was seeded and still opens with the old PINs. Afterwards the store and the keys §3.2 lists are
   gone (Bug 138).
6. **Reads fail loudly.** A seeded value that won't open under today's key stops the migration with an error
   (register C1). Nothing is written or deleted, and the user's data is left as it was.

**One test per starting state (§3.1).** Each one runs in both key forms.

| Starting state | What the test does | What must hold, beyond checks 1–6 |
|---|---|---|
| No lock (PIN never set) | Migrates silently under the empty phrase | Depth 0's view is in the space of the empty phrase; no prompt |
| PIN only | Sets up one phrase | Depth 0's view is in the phrase's space |
| Secure Mode with K duress layers, for K = 1 and K = 3 | Sets up K+1 phrases in one sitting from the real depth (Rule 2) | Each depth's view is in its own space |
| Unlocked at duress depth N (8a) | Sets up at N, then later finishes from the real depth, typing N's phrase again | After the first step, only N's view is in the new store, and the old store is intact and opens with every PIN. After the second, every depth's view is in its space and the old store is gone |
| Lock off at duress depth N (8b) | Migrates N silently under the device-only key; later the real user turns the lock on and finishes setup | Same as 8a: the old store waits for the other layers |
| Depths a coercer created (`coercerBaseDepth > 0`) | Sets up as in the K-layer case | The coercer's depths and the contacts born in them are in no space, and their rows are shredded. Everything else checks 1–6 as usual. This is the one deliberate removal, by decision 7d |

**The lock turned on and off after migration.** On every starting state, after migration:
- the lock is turned off (7a);
- it is turned on again, which reseals the space under a new phrase (7c);
- on an install that had no lock, it is turned on for the first time (§1.4).

After each step, the space shows exactly what it showed before the step, and the old phrase opens nothing.

**Interruptions and repeats.** These carry Bug 171's crash-safety tests over:
- Interrupted at each write point: nothing becomes unreadable, the next launch finishes, and a third run changes
  nothing.
- A new record is opened and compared before anything old is deleted. A faulty sealer leaves the old store whole.
- At scale (2,000 contacts across three depths, as in `KeyResealScaleTests`), time and memory are attached.

**Where they run.**
- They run on the Simulator, under `.ambientFrozenTestKeyManager`, with the KDF's cost injected (§6) and the
  store in a directory of the test's own (Bug 192).
- Variants that need a real Enclave are gated with `.enabled(if: secureEnclaveAvailable())`.
- They never run on a phone that holds real data. The device run waits for the spare phone (§8, 6) and belongs to
  stage 7.

**When they land.**
- Stage 0 builds the mock data, the literal lists and the fixture guards, which pass against today's code.
- The checks are switched on as their slices land: the vault at stage 3; contacts, photos and groups at stage 4;
  the remaining records at stage 5; every starting state and the lock toggles at stage 6.

---

## 4. From the local DB key to depth keys

**Every caller changes.** Every encrypted field is sealed today under the one hybrid local DB key
(`createHybridLocalEncryptionKey`, [Key+Manager.swift:438](../../Occulta/Services/Key+Manager.swift)). The
current callers:

| Kind | Sites |
|---|---|
| Explicit `createHybridLocalEncryptionKey()` through `Manager.Ambient` | 24 |
| Implicit `.decrypt()` | 88 |
| Implicit `.encrypt()` | 34 |
| `.encrypt(using:)` / `.decrypt(using:)` with a key derived once | 29 |

About 175 sites in all.

**What the 2026-10-15 storage changes.** Rows are sealed under a depth key or the shared key, with no per-row
keys.
- Each contact becomes one sealed blob, padded to a few fixed sizes (requirements 3, 4). The five
  `@Relationship` tables fold into it.
- The depth stamps are dropped (requirement 1).
- A group becomes one row per depth that has it (requirement 5).
- Origin lists and padding rows are new rows (requirement 2).
- Vault entries go under their own depth's key.

**What that means for the call sites.** Most field-level calls on contacts become one blob decode. The 175
sites are the scope to sweep, together with requirement 5's "not swept yet" list.

**`Contact.Profile.identifier` is a reference, not only a field** (`bugs.md` Bug 171, "What stays open" item 4;
`decisions.md`, 2026-10-21). Its base64 ciphertext is stored as a value in `Group` member slots,
`Draft.encryptedRecipientID`, the custody and shard payloads and the legacy keychain prekey tags
`prekey.<identifier>.<uuid>`, and hashed into `TrusteeTag`
([KeyReseal+Inventory.swift](../../Occulta/Services/KeyReseal+Inventory.swift), `Profile.identifier`). Bug 171's
reseal left it and every copy byte-identical under the legacy local DB key, which a holder of Q can compute. For
contacts imported from the address book its plaintext is the iOS Contacts entry ID, so each one links to a card in
the phone's Contacts. This migration is where that closes:
- Stage 4 moves the identifier into the contact's blob and rewrites the group slots and drafts that refer to it,
  in the same migration.
- Stage 5 does the same for the custody and shard payloads and `TrusteeTag`. ~~Whether a changed `TrusteeTag` still
  matches what a trustee holds needs checking first.~~ *Checked 2026-11-02:* nothing holding the reference leaves
  the phone. `TrusteeTag` only matches this phone's records against its own contacts, and a custody payload's
  `ownerContactIdentifier` is the trustee's own reference to the owner.
- ~~What the references hold instead is open, needs a decision. It must not be anything that decrypts to the
  identifier outside the contact's own depth.~~ **Decided 2026-11-02:** a random 16-byte contact ID (§8, 20).
- Not closed by it, each open, needs a decision: images taken before the migration, the old store until
  the reseal is verified (§1.2), and the legacy prekey tags in older keychain images, which outlive an app deletion (Bug 170,
  decision 19).

**Register C1 comes first.** `Data.decrypt()` turns any failure into `nil`, and `String.decrypt()` into `""`.
That is how Bugs 75–78 and 80 became silent loss. The reseal's reads must fail loudly before it ships.

**Not affected: the share extension.** It never links `Manager.Key` or `Manager.Crypto`
([ShareViewController.swift](../../ShareExtension/ShareViewController.swift), header).

---

## 5. Multiple depths

**Reading.** "Levels" here means Secure Mode's depths. If selectable security tiers are wanted instead,
Rule 3 allows only two visible states: lock off and lock on.

**What depths cost and how they change.**
- **Memory load.** Every depth's phrase has the same length (spec §3). So each depth adds 7 words to
  memorise.
- **Adding a depth.** The new depth's header slot is written, and its parent's slot gains the new key (spec
  §2, 2026-10-15). That shows across images; the spec has it as open.
- **Removing a depth: superseded 2026-10-29 by the owner.** Independent spaces share no keys, so no space can
  remove another, and there is no "remove space" action. Deleting content crypto-shreds it (§1.5), so a user who
  deletes everything in a space has emptied it. **Erase All Data erases the current space only:** it shreds that
  space's rows and nothing else's, so one forced from a duress space can't destroy the real space's data.
  - **Decided 2026-10-29: the install-wide keys stay.** Erase clears the space's rows and the share-staging
    container and key, which are transient. The identity key, the tier secrets and the Secure Enclave keys stay,
    because deleting them from one space would break every other space (`Manager.App.eraseAllData` deletes them
    today, `Manager+App.swift:47`). There is no in-app full wipe: the app can't tell a coerced wipe from a real one
    without a record only the real space has. A full wipe of the install is the iPhone's own reset, and the setup
    and Settings copy say so. An erased space still leaves the old identity key in the keychain (Bug 170, unchanged
    by this decision).
  - The text below is the 2026-10-19 decision (9a, 9b; the chain it relied on is gone).
- **Removing a depth (earlier design).** The 2026-10-15 design doesn't cover this. **Decided 2026-10-19 by the owner (9a, 9b;
  `decisions.md`, 2026-10-19):**
  - **9a, who.** Any depth can remove the depths below it. Removing one removes everything below it too, since
    it holds their keys. No depth removes itself or anything above it.
    - The same option behaves the same at every depth.
    - It replaces today's rule that only the real depth or a coercer's home depth (`coercerBaseDepth`) may
      deactivate, which needs the absolute depth numbers requirement 1 drops.
  - **9b, what.** The removed depths' header slots go back to filler, and the depth above drops their key.
    - Rows sealed only under those keys become unopenable, which requirement 2 explains as deletions. That is
      today's vault orphaning (`orphanVaultEntries`) generalised.
    - The contacts those depths created are deleted, for 7d's reason.
  - **Still open:** it shows across images the same way creating a depth does (spec §2, 2026-10-15, open).
- **Repeated images.** The spec's finding stands: a duress depth doesn't survive comparison across images
  once its phrase is surrendered. Step 16's guidance has to say so.
  **Recorded 2026-10-29 as a stated limit (Bug 120).** Independent spaces don't change it, and noise rows can't
  close it. What the design does fix, in one image and with no phrase:
  - **One table, one row shape:** each contact is one sealed blob (no per-type tables whose counts show), padded
    to a few fixed sizes, with noise rows in the same sizes (spec §2, requirements 3 and 4).
  - **No space tag on any row.**
  - ~~**Every change is "append a new row, shred the old",** so edits, additions and deletions look alike.~~
    **Changed 2026-11-01 (§8, 22):** an edit rewrites the contact's row in place under the same ID, a deletion
    overwrites it with random bytes, and an addition appends a row. Under the old scheme they never looked alike
    either: an addition only appended and a deletion only shredded.
  - It stays open in the register, as a limit and not as accepted.

**One addition to the spec's ruled-out option.** The spec names public keys with append-only storage as the
only full fix for write frequency, and rules it out for v2.0.0. Its wraps would also rest on elliptic-curve key
agreement alone. Today's hybrid local DB key doesn't: its keychain random component exists so the store needs
more than ECDH. Keeping that property would need ML-KEM, which is iOS 26+ against a deployment target of 18.6.

---

## 6. Other things it touches

- **The vault's keys** (decision 11, reframed 2026-10-19 by the owner's question "is it not better to keep vault
  data isolated?").
  - **Already depth-bound.** Under the 2026-10-15 design each depth's vault entries are sealed under that depth's
    key. A decoy can't read the real vault, which is stricter than today's single vault key for every depth.
  - **What it gives up against today's separate vault key:**
    - **11a, a key of its own.** It can be restored for free: a per-depth vault key derived from the depth key
      with a vault-only label. The unlock stays the same, and a depth's vault can then be erased on its own.
    - **11b, a second unlock.** Today the vault key is in memory only while the vault is open, after Face ID. To
      keep that, mix one Face ID-or-passcode Enclave key per install into each depth's vault key. One per
      install, so the depth count doesn't leak.
      - It keeps a keychain item (Bug 170) unless decision 15 moves it to a file.
      - It narrows the memory window.
      - This adversary has the passcode and can compel Face ID, so it mainly stops weaker attackers.
      - The cheaper alternative is an on-screen Face ID gate with no key behind it. Today the vault key accepts
        the device passcode in place of Face ID ([Key+Manager.swift:653](../../Occulta/Services/Key+Manager.swift)).
  - **Decided 2026-10-29 by the owner: 11a, plus the cheaper form of 11b.** The vault key is derived from the
    space key with a vault-only label, so a space's vault is isolated and can be erased on its own. Opening the
    vault asks for Face ID on screen, with no key behind it, as the alternative above describes. No Face ID
    Enclave key is mixed in, so there is no new keychain item (Bug 170). The gate stops weaker attackers only,
    because this adversary can compel Face ID. Today's passcode-instead-of-Face-ID fallback
    (`Key+Manager.swift:653`) is not part of the gate.
  - ~~Both open, needs a decision~~ (2026-10-19).
- **Recovery.**
  - A Shamir backup restores vault content without the phrase. Nothing restores contacts. The setup copy must
    say so plainly (spec §4, Recovery).
  - Step 11's counsel pass covers that copy.
- **Bug 92's export passphrase** reuses the keyboard (§2.2). It can ship first and field-test typing before
  anything depends on it.
- **Erase All Data and `forceDeactivateForRecovery`:** Erase All Data erases the current space only (§5,
  2026-10-29). `forceDeactivateForRecovery` drops layers at migration (7d). Header destruction is gone with the
  headers.
- **Where per-install keys live** (decision 15, added 2026-10-19; `bugs.md` Bug 170). The keychain keeps an
  app's items after the app is deleted, so Occulta's keys and their creation dates survive a deletion. So do
  the legacy prekey tags that name contacts. Enclave blobs in files in the app's container go with the app.
  - **The new per-install phrase key** could start as a blob at no cost.
  - **The identity key** can't move without a new identity, which strands every contact (Bug 82).
  - **The keys graduation retires** survive a deletion until then.
  - **Separately, Erase All Data** doesn't delete the share staging key.

  **Decided 2026-10-19 by the owner (15a–15d; `decisions.md`, 2026-10-19).**
  - **15a.** The new per-install phrase key is a keychain item, like the app's other keys.
  - **15b.** The identity key stays in the keychain.
  - **15c.** The keys graduation retires aren't moved first.
  - **15d.** Erase All Data deletes the share staging key, which stays a keychain item. This doesn't depend on the
    passphrase work. Built and merged 2026-10-19 (PR #118, with #119), so it ships in 2.0.0.

  So per-install keys keep outliving an app deletion, with their creation dates. Open, needs a decision (Bug 170): the
  legacy keychain prekeys, and the shard custody key, which waits on stage 5.
- **Device Migration** (`Docs/Features/Device Migration/FINDINGS.md`, exploratory) means a new Enclave, so
  phrases are set up again on the new phone. Out of scope here.
- **Tests.**
  - 25 test files (about 8,800 lines) use `Manager.Security` or `PINManager`.
  - `TestKeyManager` needs a depth-key path.
  - The KDF's cost must be injectable, or each derivation costs ~1 s in the suite.
  - The "data survives" reseal test (register C3, TEST-2) is required before any slice counts as done. §3.3 is its
    plan: mock data under today's encryption, one test per starting state, and the lock turned off and on.
- **Devices.** The Simulator can't unlock the vault. Timing (§7, stage 0) and every stage from 3 on need a
  physical phone that holds no real data.
- **Docs to update once decided:**
  - the spec's §1, §4 and §5;
  - ROLLOUT_PLAN's Rule 1 and stages 2–4;
  - `USER_GUIDE.md`, through counsel;
  - `SECURITY_CHECKLIST.md`'s Testing Gate;
  - `CLAUDE.md`'s crypto line, if CommonCrypto comes in (spec §4).

---

## 7. Stages and effort

**Calibration: the prekey refactor.** Its design ([Prekey Continuity](../Features/Prekey%20Continuity/DESIGN.md))
is dated 2026-10-06. Its stages merged between 2026-10-11 (PR #87) and 2026-10-15 (PR #109). That is about two
weeks from a settled design to merged. Weeks below are build time at that pace.

### 7.1 Two release orders

**A. One passphrase release.** Every data slice ships in one release. The reseal runs at phrase setup, into a
new store, with the old store as Rule 4's way back (§1.2). *(2026-10-29: no way back; the old store goes once the
reseal is verified.)*
- One reseal, and no key escrowed anywhere.
- Matches the owner's 2026-10-15 lean towards shipping all slices together (ROLLOUT_PLAN, release mechanics).
- Stages 0 and 1 can ship earlier: stage 1 through Bug 92's export passphrase.

**B. Silent reseal first.** Key slots and device slots let every install reseal in an earlier release. Phrases
come in a later one.
- The riskiest operation ships and runs alone.
- Graduation then needs a rekey, a second reseal (§1.1).
- About 2–3 more weeks than A.

**B dropped out on 2026-10-19** with key slots (§1.1). That doesn't settle whether the data slices ship
together. A is the owner's 2026-10-15 lean; ROLLOUT_PLAN's stages 2–4 split them by data.
**Decided 2026-10-29 by the owner: A, all slices together in one reseal.** With no probation week there is no way
back after the old store is deleted, so the riskiest operation runs once and is tested hard.

**Decided 2026-10-19 by the owner: the passphrase work ships in the release after 2.0.0.**
- 2.0.0 ships what is merged into `release/v2.0.0` without it.
- Stage 0's groundwork and stage 1's keyboard may go into 2.0.0 if they're ready.
- Why: the prekey records and the reseal are each a large migration, and the app sends no telemetry. Kept in
  separate releases, a failure points at one of them (`decisions.md`, 2026-10-19).

### 7.2 Stages, for order A

| # | Stage | Ships | Weeks |
|---|---|---|---|
| 0 | Groundwork | The measuring app (§8, 6); the reseal's reads fail loudly (C1); a key cache in memory only that drops the key and every decrypted record when the app goes to the background, locks or changes space, not on device lock (C2; §8, 27); a `VersionedSchema` baseline (register §G); new-store-file mechanics (Bug 168's proposal), as a plain SQLite store layer with `secure_delete` and a checkpoint after every shred (§8, 23), closed when the app goes to the background so its `-wal` is deleted, with tests that old ciphertext is gone from the file and the `-wal` is gone after closing (§8, 26); the "data survives" reseal test (C3): §3.3's mock data, literal lists and fixture guards, with its checks switched on as stages 3–6 land; PBKDF2 and Enclave timing on an iPhone 11; generator v2 (§2.3) | 1.5–2 |
| 1 | Keyboard and learning ladder | §2.2, §2.5. Can ship first on Bug 92's export passphrase | 1–1.5, alongside 0 |
| 2 | Close the design | §8's remaining open items; the model sweep for requirement 5 | 1–2 |
| 3 | Key derivation, space keys; vault into the new store | Spec §1 (PBKDF2 over word indices, the `ECDH(d, P)` term); the vault's own key and on-screen Face ID gate; each record bound to its row (step 5, §1.6) | 2–3 |
| 4 | Contacts into the new store | One padded text record per contact; photos in their own table at one size, re-encoded, with no noise rows; vault entries in their own table with noise rows; groups per space; stamps dropped; deletion that crypto-shreds; prekey blobs (D9); the ~175 sites in §4; the identifier and the group slots and drafts that refer to it (§4) | 4–7 |
| 5 | Remaining records | Backup keys, custody shards, restore records; the identifier's copies in custody and shard payloads and `TrusteeTag` (§4); the Bug 141 queue and Bug 162's open part (ROLLOUT_PLAN stage 4) | 1–2 |
| 6 | Phrase setup and the phrase lock screen | Every row of §3.1; the coercion gate (§1.3); Erase All Data scoped to one space; deleting the old store once every layer has migrated; no old-PIN fallback and no graduation | 2.5–4 |
| 7 | Copy and test period | Steps 11 and 16 through counsel; TestFlight on phones with several spaces | 1, plus ~1 calendar week: a 7-day phased release |

**Total: about 13–21 weeks of build, roughly 3–5 months.** Stage 4 and stage 2 decide where in that range it
lands. *Not re-estimated after 2026-10-29. Independent spaces drop headers, the chain, the shared key, origin
lists, graduation and the old-PIN fallback, and add the photo table and scoped erase, so the range is a guess
until stage 2 closes.*

---

## 8. Open, needs a decision

Numbered as they are being decided, one by one, from 2026-10-19. The spec's own 2026-10-15 sub-items stay open
there and aren't repeated here.

1. ~~**Adopt the 2026-10-15 storage design** (spec §2) as the shape to build.~~ **Decided 2026-10-29:** not
   adopted. Independent spaces instead (§1.5).
2. ~~**Key slots,** or rows directly under `layerKey_D` (§1.1).~~ **Decided 2026-10-19:** direct derivation.
3. ~~**Which release carries the work** (§7.1).~~ **Decided 2026-10-19:** the release after 2.0.0. ~~Whether
   the data slices ship together stays open (ROLLOUT_PLAN, release mechanics).~~ **Decided 2026-10-29:** they ship
   together, in one reseal (§7.1).
4. ~~**Rule 4's way back** through the old store (§1.2).~~ ~~**Decided 2026-10-19:** adopted, with a new store
   file.~~ **Superseded 2026-10-29:** no probation week and no way back. The reseal writes a new store file, and the
   old store is deleted once the reseal is verified (§1.2, §3.2).
5. ~~**Installs with no lock** (§1.4).~~ **Decided 2026-10-19:** migrate everyone, with an empty phrase for
   depth 0.
6. **A test phone with no real data.** Which one? As of 2026-10-19 none is cleared: the iPhone 11 still holds real
   data. Stage 0's timing and every stage from 3 on wait for one.
   *2026-11-01: a hosted test run on the iPhone 15 Pro, which also holds real data, deleted its groups (`bugs.md`
   Bug 192). Nothing hosted in Occulta.app runs on either phone.*

   **Decided 2026-11-02 by the owner: a spare phone, and a measuring app until it arrives** (`decisions.md`,
   2026-11-02).
   - **A spare iPhone with no real data,** ideally an iPhone 11, the slowest phone the app supports (it needs the U1
     chip). Stages 3 on, the migration, several spaces and stage 7's TestFlight need it; none of that is safe on a
     phone with real data.
   - **A measuring app with its own bundle ID** for stage 0's device timings: PBKDF2, the Enclave derivation,
     SQLite reads and trial decryption at scale. It uses throwaway keys and its own files, links no Occulta code
     that touches the store or keychain, and is never a test host for Occulta. iOS keeps its container and
     keychain apart from Occulta's, so it can run on a phone with real data, but each install is asked for first,
     naming the phone. ~~Not built.~~ *Built 2026-11-02 as `Tools/OccultaMeasure`, PR #155 to `develop` (not
     merged): run on the iPhone 17 Pro Simulator only, not on a device.*
7. **The coercion gate** under phrases (§1.3):
   - 7a: ~~lowering it at a duress depth~~ **Decided:** kept, built identically for every depth and install.
   - 7b: ~~lowering it at the real depth~~ ~~**Decided:** refused while duress depths exist.~~ **Superseded
     2026-10-29:** allowed in every space and on every install, with one warning, the same everywhere.
   - 7c: ~~turning it back on~~ ~~**Decided:** a new depth below, behaving like an ordinary lock-on; how is open.~~
     **Superseded 2026-10-29:** no new depth. Lock-on reseals the current space under a new phrase, as an ordinary
     install's lock-on does.
   - 7d: depths a coercer created. ~~Open~~ **Decided 2026-10-19:** dropped at setup, with the contacts they
     created. **Changed 2026-10-29:** at migration only; after it a coercer-created space is just another space.
8. ~~**Phrase setup seen from a duress depth**, and from a depth with the gate lowered (§3.1).~~ **Decided
   2026-10-19:** a decoy's setup is real and the real depth finishes later (8a); a decoy with its lock off migrates
   like an install with no lock (8b). **Changed 2026-10-29:** both kept, but the old store waits until every layer
   has migrated; Rule 2 stands for the migration (§3.1).
9. ~~**Removing a depth** (§5).~~ **Superseded 2026-10-29:** no remove action; Erase All Data erases the current
   space only (install-wide keys stay). ~~**Decided 2026-10-19:** any depth removes the depths below it, cascading;
   their data becomes unopenable and the contacts they created are deleted. How it shows across images stays
   open, with depth creation.~~
10. ~~**A setup deadline** for lock users without a phrase (§3.2).~~ **Decided 2026-10-19:** required at the
    first unlock after the update.
11. ~~**The vault's keys** (§6): 11a, a per-depth vault key derived from the depth key; 11b, a second unlock
    (an on-screen Face ID gate, or a real Face ID-or-passcode key).~~ **Decided 2026-10-29:** 11a, with an
    on-screen Face ID gate and no key behind it.
12. ~~**The wordlist**: full list or a short-prefix subset (§2.4).~~ **Decided 2026-10-19:** the full list, 7
    words.
13. ~~**VoiceOver and the suggestion bar** (§2.5).~~ **Decided 2026-10-19:** no suggestion bar, with haptic-only
    feedback; VoiceOver as in iOS's password fields, with a headphones suggestion.
14. ~~**Rehearsal reminders** after graduation (§2.5).~~ ~~**Decided 2026-10-19:** a dismissable prompt about
    monthly at unlock, plus a manual entry in Settings.~~ **Superseded 2026-10-29:** no rehearsal feature.
15. ~~**Where per-install keys live** (§6, `bugs.md` Bug 170).~~ **Decided 2026-10-19:** the keychain, for the
    new phrase key and the identity key; retired keys aren't moved; Erase All Data deletes the share staging key.
16. ~~**D2 from Bug 171** (added 2026-10-24): drop the per-guess Enclave requirement, which the spec's construction
    doesn't meet (`PASSPHRASE_LAYER_KEYS.md` §1).~~ **Decided 2026-10-29 by the owner:** the claim is dropped
    and the `ECDH(d, P)` device-binding term stays. Strength rests on 7 words through PBKDF2 (spec §4). Still to
    do: update `PASSPHRASE_LAYER_KEYS.md` §1 and `HARDENING_STEPS.md` step 2.
17. ~~**The version number of the release after 2.0.0** (added 2026-10-24), for example 2.1.0.~~ **Decided
    2026-10-29:** 2.1.0. It names the
    release branch (`release/v<version>`) and the prefix of the passphrase work's feature branches. Nothing on the
    wire depends on it, since the work is local storage.
18. ~~**What a newer build does with a store an older build wrote to in the meantime** (added 2026-10-24; §1.2,
    ROLLOUT_PLAN's "A downgrade loses nothing"). Left open by decision 4.~~ **Decided 2026-10-29 by the owner:**
    a downgrade after migration is not supported, and the release notes say so. The old store is gone, so an
    older build finds no data and starts empty, and the new store stays on disk for the next update. Same as D6
    of Bug 171 and Bug 168. The one window is 8a's migration state, where the old store lasts until every layer
    has migrated.
19. ~~**Bug 170's leftovers** (added 2026-10-24; §6, `bugs.md` Bug 170): the legacy keychain prekeys, whose tags name
    contacts and outlive an app deletion until they retire, and the shard custody key, which waits on ROLLOUT_PLAN
    stage 4.~~ **Decided 2026-10-29:** left in Bug 170.
20. **What the identifier's references hold** (added 2026-10-30; §4, `bugs.md` Bug 171 item 4) once
    `Contact.Profile.identifier` moves into the contact's blob: group slots, drafts, custody and shard payloads and
    `TrusteeTag` hold its legacy ciphertext today, which a holder of Q can decrypt.

    **Decided 2026-11-02 by the owner: a random contact ID** (`decisions.md`, 2026-11-02).
    - **The ID:** every contact gets a random 16-byte ID when it is created, however it arrives: imported, created by
      hand, exchanged or from a card. The migration gives each existing contact one. It lives inside the contact's
      sealed record.
    - **References** (group member slots, drafts, custody and shard payloads, the shard records) hold that ID, and
      only inside rows sealed under the same space key, so nothing outside the contact's own space decrypts to it.
      `TrusteeTag` stays a hash, now of the ID, so its code doesn't change.
    - **The address-book ID** is used once at import, to fetch the card (`ContactsListV2.swift:313`), and never
      stored. Nothing reads it afterwards today either: there is no re-sync and no duplicate check. So no space's
      records link a contact to a card in the phone's Contacts, and an imported contact can't be told from any
      other.
    - **Fixed width** removes the reason for `Group`'s 128-byte slot padding (address-book IDs run up to 88 bytes) and
      for hashing into `TrusteeTag` (Bug 145).
    - **Nothing leaves the phone:** every holder of the reference is local, so changing it breaks nothing a
      trustee or contact holds.
    - **Not adopted:** keeping the old identifier, decrypted at migration, inside the sealed rows. Less rewriting, but
      the address-book link would survive for anyone holding a space's phrase, even for a contact renamed in Occulta.
    - **Still open, as before** (§4): images taken before the migration, and older keychain images with the legacy
      prekey tags (Bug 170, decision 19).
21. **How many noise rows there are, and when they are written** (added 2026-10-30; §1.5, §5). The migration has to
    write noise rows, or a table's total shows how many contacts every space holds together: an install with 40
    contacts and no duress space must look like one with 30 visible and 10 hidden. ~~Nothing says how many, whether
    the count is drawn per install, or whether it changes after migration.~~ The prekey dummies had the same question
    ("a range of 32–128… not decided", spec §2); D9 made that one moot, but not this one. A space that migrates
    later than the others (8a, 8b) appends noise rows with its batch too (item 25, decided 2026-11-01); how many is
    part of this item.

    **Decided 2026-11-01 by the owner for the contact table:** the count is drawn per install, uniformly from
    50–1,000, and never stored.
    - **When:** in the migration's one sitting; at first launch on a fresh install, so the two look alike; and as a
      fresh draw from the same range with a space that migrates later (item 25). Never after that: deleted rows,
      shredded in place (item 22), grow the unopened set with use.
    - **Why uniform:** every count of unopened rows up to 1,000 is then equally likely with or without a hidden
      space. The range is public with the code, so only the cap says anything: right after migration, more than
      1,000 unopened rows proves a hidden space. A hidden space of H contacts stays unprovable on (951 − H) / 951 of
      installs: 95% at 50, 79% at 200, 58% at 400. Deleted rows blur it further once the phone is used.
    - **Why absolute:** a range scaled with contact counts would let a large real space show behind a small decoy.
    - **Cost at the cap:** about 8 MB, and about 4 ms to try and reject 1,000 noise rows on an iPhone 15 Pro (5 ms on
      the iPhone 17 Pro Simulator; 8,220-byte records, `ContactRecordCryptoMeasurementTests.measureAtScale`, §1.5); a
      failed tag check skips the JSON decode that dominates a real open. An iPhone 11 is unmeasured (decision 6).
    - ~~**Still open, needs a decision:** noise rows' sizes have to follow how real records spread over the size
      buckets, decided with the blob sizes; the other space-sealed tables (vault entries, groups, the backup-key,
      custody and restore records) each show their own count and need their own draw and range. The photo table is
      its own item (§1.5).~~

    **Decided 2026-11-02 by the owner: one table and one row size for every small space-sealed record**
    (`decisions.md`, 2026-11-02).
    - **One size, about 8 KB.** The fullest measured contact record fits with room: an ML-KEM-1024 key, two P-256
      keys and the 23-prekey peak come to about 5.5 KB encoded. Fields get limits so no record overflows, and the
      size is checked against the largest real record when it is built. With one size, noise rows have no spread
      over buckets to match, so the sizes question goes away.
    - **One table** holds contacts, groups, backup keys, custody shards and the shard and restore queue records
      (`PendingShardDistribute`, `PendingShardStatusUpdate`, `PotentiallyLostShard`, `ReconstructShard`,
      `PendingShamirSecretRestore`). A record's type is inside its seal, so no per-type count shows in an image, and
      the noise draw above covers every type. Several of these hold zero to a few rows per space, so a table of
      their own would show another space's row on its own.
    - **Cost:** a group or custody shard takes 8 KB instead of about 1 KB; there are tens of them. Unlock already
      tries every row.
    - **Kept out:** photos and vault entries, whose size is the user's content. *Decided 2026-11-02 (§1.5):* photos
      in a table of one size with no noise; vault entries in a table of 4 KB rows with noise drawn from 10–200.
    - **Not adopted:** a table per type, each with its own size, draw and range: about seven ranges for tables
      with small, uneven real counts, and each count still shows on its own.
22. **The table only grows** (added 2026-10-30; §1.5). "Append a new row, shred the old" keeps every shredded row
    as noise, and no space can remove one, since nothing tells it from another space's row. So every edit adds a
    row for good. If consuming a prekey rewrites the contact's record (D9, stage 4), every message received does
    too. Unlock trial-decrypts every row, so its cost and the store's size grow with every write ever made, not with
    the contact count; the "10k rows" estimate counts contacts. The locator tag (§1.5) makes each check cheaper but
    doesn't reduce the count.

    **Decided 2026-11-01 by the owner: an edit rewrites the row in place** (`decisions.md`, 2026-11-01). This
    replaces "append a new row, shred the old" (§1.5, §5).
    - **An edit** overwrites the contact's row under the same random ID with a fresh seal, in one transaction. **A
      deletion** overwrites it with random bytes, as before. **An addition** appends a row. The same holds for every
      space-sealed table.
    - **Growth:** the table grows only with rows ever added, plus noise. Edits and received messages (D9) add
      nothing. Under append-and-shred, 20 messages a day would have added about 7,300 rows, about 60 MB and 30 ms of
      unlock a year, for good.
    - **One image:** no difference. The plain SQLite store (item 23) has no `Z_OPT`, no history and no insertion
      order, so a rewritten row looks like any other.
    - **Across images:** an edit shows one changed row, where append-and-shred showed a changed row and a new one.
      A row that changes repeatedly is live, but the chain of appended and shredded rows linked the same way. Part
      of Bug 120's stated limit either way. A record that moves to another size bucket changes its row's size,
      which says what a shred at one size and an append at another said.
    - **What append-and-shred claimed:** that edits, additions and deletions look alike (§5). They didn't: an
      addition only appended and a deletion only shredded. Its other reason was SwiftData's `Z_OPT`, which the plain
      store doesn't have.
    - **Item 21:** unchanged. Its numbers are for the state right after migration; deleted rows still blur it later,
      edits no longer do.
    - **Not adopted:** a free list sealed in each space, so a space reuses rows it shredded (more machinery, no gain
      over rewriting in place), and compaction (no space can tell its own shredded rows from others).
23. **SwiftData's own columns and history** (added 2026-10-31; §1.5, `bugs.md` Bug 190). §1.5 says a deleted row,
    another space's row and a noise row look the same. In a SwiftData table they don't:
    - Shredding in place is an update, so it raises the row's `Z_OPT` to 2 while live and noise rows stay at 1.
    - Noise rows written in one batch at migration take one run of `Z_PK` values.
    - The persistent history tables (`ACHANGE`, `ATRANSACTION`) log every append and every shred with its time. That
      is the series Bug 120 says a duress space can't survive, in one image. They are in every shipped store today.

    ~~The options are in Bug 190: drop the history, shred by delete and insert in a random order, or keep these tables
    outside SwiftData.~~ **Decided 2026-11-01 by the owner: the new store file is plain SQLite** (`decisions.md`,
    2026-11-01). It holds every table sealed under a space key (vault entries, contacts, photos, groups, and the
    backup-key, custody and restore records) through the `sqlite3` C API. *(2026-11-02: the small records share one
    table, item 21.)* Each table is `WITHOUT ROWID`, keyed by a
    random 16-byte ID, with the sealed record as its only other column. That removes `Z_OPT`, insertion order, the
    write counters and the history by construction, and keeps an append and its shred in one transaction.
    Install-wide state stays in SwiftData, where Bug 190 stays open. Measured first: opening, changing and resealing
    100 records takes about 9 ms, plus about 1.6 ms for the Enclave derivation, on the iPhone 17 Pro Simulator
    (`ContactRecordCryptoMeasurementTests`). Open, needs a decision: whether the SQLite header or page placement
    says anything about write order; not checked.
24. **A known contact's bundle failing to open is the rejection oracle again** (added 2026-10-31; §1.5,
    `Docs/Bugs/v1.10.0/Non-Safe-Sender-Rejection-Is-A-Duress-Detection-Oracle.md`). The 2026-10-29 rule above
    doesn't cite that document's inbound-path analysis, which removed exactly this behaviour in `b1f9045`. Today a bundle from a contact
    hidden at the current depth opens and shows the sender's name (`identifyOwner` reads `fetchAllContacts()`,
    which filters on `deletionToken` only).
    - **What returns:** a coercer sends, or re-opens, a file from someone they know you paired in the real space.
      The transport names the sender before Occulta runs. In the duress space the file shows the corrupt-file
      screen; in the real space it would open. A file from a known person that won't open is the signal the
      2026-08-08 decision removed, and identical wording didn't stop it being one then.
    - **What is different now:** the same screen appears in every space for a file from a deleted contact, so "I
      deleted them" covers it. ~~Whether that cover is enough is the decision; the 2026-08-08 analysis had the same
      cover available (a hidden contact was absent from the list) and still counted rejection as a tell.~~
      **Decided 2026-10-31 by the owner: the cover is enough** (`decisions.md`, 2026-10-31). The duress list already
      lacks the contact, so the story is needed either way, and a refusal that says "deleted" agrees with the
      list. The screen reads "The contact who sent this message was deleted or cannot be found" at every depth,
      for every bundle whose sender matches no contact. Today's app adopts the same refusal for a contact hidden at
      the current depth; not implemented.
    - **What the rule fixes:** three things that document accepts or leaves open today. The hidden contact's
      content is never decrypted under duress (C1). The name no longer renders for a contact missing from the
      list (the 2026-08-13 presence oracle). Retained `.occ` files from a hidden contact can't be re-opened on
      demand (its 2026-10-23 case A).
    - **It may be forced:** the duress space holds neither the sender's public key nor its prekey blobs (D9), so
      it may have no way to open the bundle at all. Not checked against the long-term slot's derivation.
25. **A write that reseals all of one space's rows at once groups them** (added 2026-10-31; §1.1, §1.5, Bug 120).
    Rows that change together across two images belong together. With no phrase, an examiner gets which rows make
    up a space and how many it has, which §1.5's "no space tag" is meant to hide. Raised by the owner while ruling
    out a field inside the blob that every unlock changes, which would do this on every use; that idea is dropped.
    ~~The design already has writes of this shape, each open, needs a decision:~~
    - ~~a rekey, which §1.1 says regenerating an exposed phrase and graduation each need;~~
    - ~~removing a space, which shreds all its rows in one pass;~~
    - ~~the migration, if each space's rows are written as one batch. Under the plain SQLite store (§8, 23) the
      random key gives the batch no order, but where its pages land in the file isn't checked.~~

    ~~Spreading such a write over time, or doing it together with writes to other rows, would blur the group.
    Neither is designed.~~

    **Decided 2026-11-01 by the owner.** This is Bug 120 narrowed: any edit in a hidden space already shows across
    images that one exists, and a whole-space write adds that space's size and its full set of rows. Graduation and
    a remove-space action are gone (§3.2, §5), so the writes of this shape are four:
    - **Erase All Data** (§5) shreds the current space's rows. The group is a space that no longer exists, so it
      shows nothing about data still held. Nothing to fix.
    - **A rekey after an exposed phrase** (§1.1) has to overwrite the old rows, since the exposed phrase and this
      phone still open them, so the count is exact. Appending noise rows can't hide it, and replacing noise rows is
      out because no space can tell noise from another space's rows (Bug 120). Part of Bug 120's stated limit.
    - **Lock-on** (7c) reseals the space under the new phrase. Part of Bug 120's stated limit too: while the lock
      was off, anyone who could unlock the phone read the whole space, as the lock-off warning says. Leaving the
      old rows in place as noise and appending the new ones with noise rows would hide the size only from someone
      with an image from that time who couldn't unlock the phone. Not adopted.
    - **The migration** (§3.1). Under Rule 2 every space is written in one sitting into a new file that no earlier
      image holds, so there is no group. In the 8a/8b exception a space migrates later, as one batch, which shows
      its size. That batch also appends a random number of noise rows; how many is settled with item 21. Under the
      plain SQLite store (§8, 23) the random key gives the batch no order, but where its pages land in the file
      isn't checked (item 23's open sub-question).

    Spreading these writes over time was not adopted: it keeps erased or exposed data readable for longer.
26. **Whether an overwritten row is gone below SQLite** (added 2026-11-01; §1.5, §5; not verified). A shred
    overwrites a row with random bytes, and under independent spaces that is the only way a row goes: the key it was
    sealed under comes from a phrase and the device's Enclave key, and neither can be destroyed (Erase keeps the
    install-wide keys, §5). So an old copy of the ciphertext anywhere on the phone still opens with the phrase on
    this phone. Today's rows are under the local DB key, which a rotation or a full erase does destroy.
    - **SQLite: covered as today's app does it.** `secure_delete` zeroes the freed cell, and
      `PRAGMA wal_checkpoint(TRUNCATE)` (`OccultaApp.swift:180`) moves the WAL's frames into the file and truncates
      it. The new store layer needs a test that, after a shred and a checkpoint, finds the old ciphertext in neither
      the file nor its `-wal`.
    - **APFS: not checked.** Truncating the WAL and rewriting a page free blocks without overwriting them. A logical
      or full-file-system extraction reads files and doesn't see free space; a raw volume image with the file's key
      might. Whether a truncated file's freed blocks stay under its own key, and whether deleting the `-wal` and
      letting SQLite recreate it would discard that key, isn't known.
    - **Flash: not checked.** Stale NAND pages need a chip-level read and the device's keys.
    - ~~**Open, needs a decision:** what to verify, and whether the store deletes its `-wal` rather than truncating it.
      A destroyable per-space secret would close it, but it would be a per-space record, which §1.5 rules out.~~

    **Decided 2026-11-02 by the owner** (`decisions.md`, 2026-11-02). Since item 22 this covers every edit too: the
    old version of a rewritten row opens with the same phrase.
    - **A store-layer test** (stage 0): after a write, a shred and a checkpoint, the old ciphertext is in neither
      the file nor its `-wal`.
    - **The store closes when the app goes to the background,** when the key cache drops (item 27); nothing can
      read it without the key then. SQLite deletes the `-wal` when its last connection closes, so the WAL's blocks
      go with its file's key instead of staying freed under a key that still exists. iOS gives each file its own
      key (Apple's documented design, not verified here).
    - **A second test:** after closing, the `-wal` file doesn't exist. It catches a persistent WAL, which Apple's
      SQLite build may default to; if it does, the store turns it off.
      *Simulator, 2026-11-02 (`Tools/OccultaMeasure`, PR #155):* it does. Persistent WAL is already on before any
      PRAGMA, and the `-wal` and `-shm` stay after the last connection closes (the `-wal` at 0 bytes after a
      `TRUNCATE` checkpoint). The store has to turn it off (`SQLITE_FCNTL_PERSIST_WAL`). Not yet confirmed on a
      device.
    - **Open, needs a decision:** stale copies of the main file's pages in APFS free blocks and flash stay under the
      file's key until reused. Reading them takes a raw volume or chip-level image, the file's key and the space's
      phrase; logical and full-file-system extractions read files, not free space.
    - **Not adopted:** rotating the file on going to the background after any write (`VACUUM INTO` a new file and
      delete the old one, discarding its key and every stale copy). About 40 MB written per session at 5,000
      contacts, nearly every session since received messages rewrite records, against that narrow attacker.
27. **What the key cache holds, and when it drops it** (added 2026-11-01; stage 0, register C2, §1.5). One Enclave
    ECDH costs about 4.6 ms on an iPhone 15 Pro (§1.5's measurements), and a phrase-derived key can't be re-derived
    without the phrase, so a key is derived once and kept for the session. Caching is no weaker than today's
    re-derivation: code running in the app while the phone is unlocked can ask the Enclave for the key at will.

    **Decided 2026-11-01 by the owner:**
    - **Memory only,** as a `SymmetricKey`: never on disk and never copied into `Data`. Swift can't promise a copy is
      wiped, so there are as few copies as possible.
    - **Dropped when the app goes to the background,** not on device lock. iOS suspends a backgrounded app, and a
      suspended app runs no code, so it can't react to the lock; the key would stay in RAM on a locked phone, where an
      after-first-unlock memory dump reads it. Also dropped when the app locks itself and when the space changes, so a
      space's key never outlives its session.
    - **Every decrypted record goes with the key.** Unlock opens every record (§1.5), so a dropped key with the
      plaintext left in memory protects nothing. Re-opening on return is cheap: 37 ms for 1,000 records on the
      iPhone 15 Pro.
    - **The same holds for today's local DB key** (C2).

    ~~**Open, needs a decision:** a grace period, returning to the app without the phrase.~~ **Decided 2026-11-02 by
    the owner: a 5-minute grace, as today** (`AppScreen.swift:53`; `decisions.md`, 2026-11-02).
    - **What stays:** on going to the background the key and every decrypted record are dropped as above. Only a
      copy of the space key stays in memory, wrapped by an Enclave key made for the session, never stored, and usable
      only while the phone is unlocked.
    - **Return within 5 minutes** of going to the background: one Enclave call (about 4.6 ms) unwraps it, and the
      records are re-opened (37 ms per 1,000). Later, or after iOS kills the app, the phrase is needed. The wrapped
      copy is dropped when the 5 minutes run out on return, when the app locks itself and when the space changes.
    - **Every depth alike** (Bug 41).
    - **A memory dump of a locked phone** gets only the wrapped copy: the Enclave refuses while the phone is locked.
      The copy never reaches disk, where it would be §1.1's device slot, which older images unwrap.
    - **What it leaves, as today's PIN grace does:** someone who takes the phone unlocked, or compels its passcode,
      within 5 minutes of the user leaving Occulta opens the space last open with no phrase. A suspended app can't
      see a device lock, so the grace counts time in the background, not locks. If the last space was the real one,
      it is exposed; step 16's guidance should say so.
    - **Not adopted:** no grace, which asks for 7 words on every return to the app.
28. **Rolling a row back to an older version of itself** (added 2026-11-02; §1.6, step 5). Binding a record to its
    row ID stops it being copied onto another row, not onto its own row from an earlier image. An edit rewrites a
    row in place under the same ID (item 22), and the older ciphertext still opens (item 26). Someone who can write
    the store can bring back a deleted contact's record, or a contact's earlier keys, with no phrase. Closing it
    needs something per space that changes with every write, which §1.5's "no per-space record" rules out. Open,
    needs a decision.
29. **What the migration does with data that doesn't map one to one** (added 2026-11-03 while writing §3.3's
    tests; not decided). §3.3's expectations need both answers.
    - **A contact today's code shows at several depths.** Most contacts are visible everywhere (`visibleThroughDepth`
      holds `Int.max`), so under 8a each space that can see one receives its own copy. Open, needs a decision:
      - whether the copies share one random ID (§8, 20) or get one each;
      - what happens to the prekey state, now copied into every space. A prekey consumed in one space is still
        listed in the others, while its private key, held once in the Enclave (`PrekeySecretsManager`), is gone.
    - **Records that don't fit their row.** The decided sizes are 8 KB for a small record, about 3.5 KB of text for
      a vault note and 24 KB for a photo (§1.5, §8, 21). Today's store has no such limits. Open, needs a decision
      for a contact record or a note that is too large: failing the migration loudly, splitting the record, or
      raising the size.
      - A photo is re-encoded until it fits, by decision, so only a photo that still doesn't fit at the lowest
        quality is a case to cover.
30. **One person paired in two spaces** (added 2026-11-03). Open, needs a decision.
    - **How it happens.** Any user can pair the same person in two spaces. A coercer can force it: two travel
      companions who hold each other behind a phrase are told to pair in the decoy.
    - **What breaks.** There is one identity per install (15b), and `senderFingerprint` is
      SHA-256(identity key ‖ nonce) (`Contact+Model+Profile.swift:18`). So both spaces match the sender, and §1.5's
      rule for another space's bundle never fires. What happens next depends on the slot:
      - **One-time prekey, last-resort prekey, `.longTermFallback`:** the file fails to open in the space whose
        pairing didn't seal it. Prekeys are per pairing, and so are the ML-KEM secrets (`QuantumKeyMaterial`:
        "Cannot be rederived"). The space shows an error for a contact it holds, not item 24's screen.
      - **`.longTermNoPQ`** (either phone below iOS 26, or a pairing without ML-KEM): plain ECDH between the
        identity keys, so the file opens in every space that holds the sender. The decoy shows the hidden pairing's
        message. With no batch of its own pending, it also sends the sender a fresh batch (Receiving, step 6),
        which mixes the two pairings' prekey state.
    - **When the long-term slot is used.** Not when one-time keys run out: the last-resort key is never removed by
      use, so senders stop there. It is used:
      - for the first messages after pairing ("two fallback messages each way bootstrap a new pair");
      - for every identity challenge (`IdentityChallenge+Manager.swift:504`), which a coercer holding either phone
        can start;
      - for a contact on a build older than last-resort keys.
    - **Proposed by the owner (2026-11-03): an ID that tells which space's pairing sealed a bundle.**
      - *Per pairing, not per space.* A space-wide ID sent to every contact would be the space identifier §1.6
        says doesn't exist. Contacts could compare it. A coercer holding a peer's phone that has two pairings with
        you would see two IDs, which proves two spaces.
      - *What it would be.* A random 32-byte secret, exchanged at pairing, held only in the contact's sealed record
        (no keychain item, nothing outside the space).
    - **Two uses, either or both:**
      - *Routing:* `senderFingerprint` = SHA-256(pairing secret ‖ nonce). The space whose pairing didn't seal the
        bundle finds no match, and §1.5's rule applies as decided. It also means only the two parties can test a
        captured file for its sender; today anyone holding the sender's public key can.
      - *Key binding:* the secret mixed into every slot's derivation (`TransportKeyDerivation`). `.longTermNoPQ`
        then fails outside its pairing's space even if routing were bypassed, and the NoPQ modes need the space's
        phrase, which narrows the spec's "gap" (`PASSPHRASE_LAYER_KEYS.md`, ML-KEM modes).
    - **What it costs, each open:**
      - a wire-format change: the pairing exchange, the fingerprint and the derivation change, so a new bundle
        version and new interop vectors;
      - existing pairings have no secret. One could be sent inside a prekey-sealed message, with the identity
        fingerprint kept until both sides hold it. Until then, and for peers on older builds, this item stays open
        for that pairing;
      - a group bundle carries one `senderFingerprint` for every member (`Crypto+Manager+GroupEncrypt.swift:281`),
        and a per-pairing secret differs per member. The fingerprint would move into each member's slot, or
        receivers would try each slot;
      - a card's first message is fingerprinted by the card's key (`ContactManager+Cards.swift:722`), before any
        pairing exists; the card would carry the secret;
      - item 29: copies of a contact made by the migration would share one pairing and its secret, so this doesn't
        separate them.
    - **What each use gains** (2026-11-03):
      - *Routing* is needed for two pairings to work at all: only the space whose pairing sealed a file matches it,
        and the other shows item 24's screen. It also takes sender testing away from third parties: today anyone with
        the sender's public key can test a captured file, which includes every contact of theirs and a coercer holding
        any of those phones.
      - *Key binding* closes a measurable gap for the NoPQ modes only. Today a `.longTermNoPQ` file needs the
        identity key, in the keychain behind the passcode, and the sender's public key, so it opens outside the app
        with no phrase. So does a `.forwardSecretNoPQ` file whose prekey is still unused. With the secret in the
        derivation, both also need the contact's sealed record, so the phrase. With ML-KEM it adds nothing: those
        modes already need the ML-KEM secrets in the sealed record. The gain lasts while phones below iOS 26 and
        pairings without ML-KEM remain, a real share at a deployment target of 18.6.
      - *Neither* helps against someone with the space's phrase, who gets the record and the secret with it, or with
        item 29's copies.
      - *Cost:* the secret, the pairing-exchange change and the version bump are paid once for both. Key binding
        then adds one input to the derivation. Routing is the larger part, through the group change above.
      - *Recommended, not decided:* both. `senderProof` (`Contact+Manager.swift`, step 5.5), which today
        authenticates the sender's public key, would also cover the pairing secret, so the routing field is checked
        no less strictly than today.

---

## Related tracked items

[`bugs.md`](../Features/Secure%20Mode/bugs.md) and the register stay canonical. These are the items this plan
depends on or changes.

| Item | Summary | Status | Here |
|---|---|---|---|
| Bug 37 | Re-enable PIN fails silently at a lowered gate with an unknown PIN | Closed (fixed) | §1.3: the fix has no phrase equivalent yet |
| Bug 62 | `pinCollision` PIN oracle | Open | Gone with the old store once the reseal is verified (§3.2) |
| Bug 92 | Exported backup opens with the backup key alone; opt-in export passphrase unbuilt | Open, re-scoped 2026-09-24 | §6: shares the keyboard |
| Bug 109 | Per-depth keys leave an authentication-failure tell | Closed moot, 2026-09-10; spec §2 (2026-10-15) argues an all-or-nothing row isn't this tell | §4, §5 |
| Bug 119 | Vault key is device-level; one key opens every depth | Open | The whole plan |
| Bug 120 | Write frequency across images shows the real depth | Open in the register; recorded 2026-10-29 as a stated limit under independent spaces: a duress space protects against one image, not a series | §5 |
| Bug 123 | Small sealed fields share one AAD | Closed, subsumed into 119 | Stage 3 (step 5, §1.6) |
| Bug 138 | A migration destroyed the only copy before saving the replacement | Fixed 2026-09-26 | §1.2: the old store survives until the reseal is verified |
| Bug 139 | Keys from an interrupted rotation never deleted | Fixed 2026-09-26 (wipe) | The reseal's rule: interruption leaves nothing |
| Bug 141 | Depth-blind owner queue and watch rows | Fixed 2026-09-27; sealing per depth open | Stage 5 |
| Bug 148 | A file opened from outside shows before the PIN screen | Fixed 2026-09-28 | A file arriving behind the lock must still wait, and with phrases it also has no key to open with |
| Bug 162 | A trustee's piece count shows how many depths have a backup | On-screen count and manifest size fixed (PR #114); stored rows and piece dates open, needs a decision | Stage 5 |
| Bug 168 | A downgrade migrates the store back and drops what the older schema lacks | Accepted 2026-10-16 for the prekey records; for the passphrase migration, a new store file with no way back, and a downgrade after migration not supported (decision 18, 2026-10-29) | §1.2, stage 0 |
| Bug 170 | Deleting the app leaves its keychain items, including prekey tags that name contacts | Keys stay in the keychain by decision 15 (2026-10-19); the share key's erase fix built and merged (PR #118, 2026-10-19); legacy prekeys and the custody key open, needs a decision | §6, decision 15 |
| Bug 190 | SwiftData's persistent history logs every write with a time; `Z_OPT` marks rows updated in place | Filed 2026-10-31. For the new store, decided 2026-11-01: plain SQLite, so none of it applies there. For the SwiftData store that remains, and for today's app, open, needs a decision | §8, 23 |
| Register C1 | Decryption failure not representable | Open, P1 | Stage 0 |
| Register C2 | Local DB key re-derived per operation; no cache | Open, P1. One Enclave ECDH measured at about 4.6 ms on an iPhone 15 Pro (2026-11-01); the cache's rules decided 2026-11-01 | Stage 0; §8, 27 |
| Register C3 | No key-manager seam; no "data survives" reseal test | Open, P1, as recorded. The seam now exists (`Manager.Ambient`, `TestKeyManager`); the test doesn't. Its plan for this migration is §3.3 (2026-11-03) | Stage 0, then stages 3–6 |
| Register §G | No `VersionedSchema` | Open | Stage 0 |

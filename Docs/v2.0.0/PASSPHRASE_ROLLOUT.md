# v2.0.0 — Passphrase Rollout

**Status:** Proposed, 2026-10-19. Nothing here is decided. Every item in §8 is open, needs a decision.

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
waiting for this work, and a downgrade must lose nothing, through a new store file (proposed, not decided).

**What is new here.**
- Phrase entry and learning (§2).
- Each starting state's migration (§3).
- Rule 4's way back (§1.2).
- The coercion gate under phrases (§1.3).
- Installs with no lock (§1.4).
- Key slots as an option (§1.1).
- Stages and effort (§7).

Code references are against `75e86c39`.

---

## 1. Proposals and findings

### 1.1 Key slots: an option, with a narrow gain

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
**Open, needs a decision.**

### 1.3 The coercion gate has no phrase equivalent yet

Today the user chooses the PIN. Two coercion paths depend on that, and so does an absolute depth number.

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

**Open, needs a decision.**

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
depth's phrase in one sitting. **Open, needs a decision** (§3.1).

### 1.4 Installs with no lock

The 2026-10-15 storage doesn't say what an install with no app lock does. Two options:

1. **It stays on today's store and key until a lock is turned on,** which runs the migration then. The code
   keeps two formats for as long as such installs exist.
2. **It migrates too,** with depth 0's key derived without a phrase (a fixed empty input), or held in a device
   slot (§1.1). The code has one format. Turning a lock on later reseals depth 0, or rewraps it with §1.1's
   cost.

Either way:
- an install with no lock keeps today's protection;
- whether an install has a lock stays visible, as it is today through `sealedNormalVerifier`.

**Open, needs a decision.**

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

**Proposed design.**
- In-app letter keys. Letters that can't continue any list word are disabled, so a typo can't happen.
- A word commits when its prefix is unique. A suggestion bar appears from the third letter.
- Committed words show as dots, with press-and-hold to show them.

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

**Open, needs a decision.**

### 2.5 Learning, and where gamification fits

Memorising is the real burden, more than typing: 7 random words per depth, so 21 for someone with two duress
layers. Gamification goes there.

- **Setup ladder.** See the phrase → fill 2 gaps, choosing from 4 words → put the shuffled words in order →
  type it unaided. Each step must pass before the next.
- **Probation progress.** Rule 4 becomes a ring that fills with correct entries spread over several days.
  When it completes, the app graduates (§3.2).
- **Rehearse.** At the real depth, check any depth's phrase without changing depth. It counts toward that
  depth's Rule 4 progress. After graduation, duress phrases are rarely typed. A periodic rehearsal prompt
  would need a stored "last rehearsed" per depth. **Open, needs a decision.**

**Constraints.**
- No notifications or badges; `OSTraceTests` forbids them.
- The only stored state is the Rule 4 progress. Per the 2026-10-15 requirements:
  - it lives in rows in the general pool, sealed under each depth's key (requirement 7), not in a
    32-entry array where only real entries change;
  - it names no absolute depth (requirement 1).
- The screens are the same at every depth. A duress depth shows only its own phrase's progress.
- Every lock user gets them (Rule 3).

**Open, needs a decision:**
- VoiceOver speaks each key and suggestion aloud on a custom keyboard.
- The suggestion bar shows the word being typed to any camera in view.

---

## 3. Migrating installs that have a PIN

### 3.1 Starting states

Assuming §1.2: the reseal happens at phrase setup, into a new store.

| Today | At phrase setup | Notes |
|---|---|---|
| No lock | Nothing, or the migration of §1.4 | §1.4 |
| PIN only | 1 phrase; the reseal into the new store | The old store stays until graduation |
| Secure Mode with K duress layers | At the real depth, after the master PIN: K+1 phrases in one sitting (Rule 2), then one reseal of every depth | Only the real user can give every phrase |
| Unlocked at duress depth N | The prompt must look the same as at the real depth. Setup can't complete there, because Rule 2 needs every phrase | **Open, needs a decision** |
| Gate lowered at depth N | Presents as an install with no lock. How the real user gets back to set up | **Open, needs a decision** |
| Depths a coercer created (`coercerBaseDepth > 0`) | The real user doesn't know their PINs. Drop them at setup, as `forceDeactivateForRecovery` does today? | **Open, needs a decision** |

### 3.2 Probation and graduation

**During probation.** Until graduation, the lock screen asks for the phrase. Every lock user also gets
"use my old PIN", which opens the old store as it was at setup (§1.2).

**Graduation.** When every phrase is proven, these are deleted together:
- the old store;
- the local DB Enclave key and the keychain random (`local.db.random.key.occulta`);
- the Secure Mode PIN Enclave key (`app.layer.key.occulta.v1`).

**What the deletion shows.** Keychain items carry creation dates, and an item's absence is visible. With
§1.4's first option, the old key's absence says the install has a lock. That is no more than today's
verifier scalar says.

**Open, needs a decision:** a deadline after which a lock user who hasn't set up a phrase must.

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
- **Removing a depth.** The 2026-10-15 design doesn't cover this. Proposed:
  - the depth's header slot goes back to filler, and its parent's slot drops its key;
  - rows under its key become unopenable, which requirement 2 explains as deletions;
  - it shows across images the same way creation does.

  **Open, needs a decision.**
- **Repeated images.** The spec's finding stands: a duress depth doesn't survive comparison across images
  once its phrase is surrendered. Step 16's guidance has to say so.

**One addition to the spec's ruled-out option.** The spec names public keys with append-only storage as the
only full fix for write frequency, and rules it out for v2.0.0. Its wraps would also rest on elliptic-curve key
agreement alone. Today's hybrid local DB key doesn't: its keychain random component exists so the store needs
more than ECDH. Keeping that property would need ML-KEM, which is iOS 26+ against a deployment target of 18.6.

---

## 6. Other things it touches

- **Vault Face ID.** The 2026-10-15 depth keys replace the vault key for the data they cover. Today the vault
  key accepts the device passcode in place of Face ID
  ([Key+Manager.swift:653](../../Occulta/Services/Key+Manager.swift)), so Face ID adds no protection against
  this adversary. Keep it as a second gate on screen, or drop it: **open, needs a decision.**
- **Recovery.**
  - A Shamir backup restores vault content without the phrase. Nothing restores contacts. The setup copy must
    say so plainly (spec §4, Recovery).
  - Step 11's counsel pass covers that copy.
- **Bug 92's export passphrase** reuses the keyboard (§2.2). It can ship first and field-test typing before
  anything depends on it.
- **Erase All Data and `forceDeactivateForRecovery`** become header destruction.
- **Device Migration** (`Docs/Features/Device Migration/FINDINGS.md`, exploratory) means a new Enclave, so
  phrases are set up again on the new phone. Out of scope here.
- **Tests.**
  - 25 test files (about 8,800 lines) use `Manager.Security` or `PINManager`.
  - `TestKeyManager` needs a depth-key path.
  - The KDF's cost must be injectable, or each derivation costs ~1 s in the suite.
  - The "data survives" reseal test (register C3, TEST-2) is required before any slice counts as done.
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
new store, with the old store as Rule 4's way back (§1.2).
- One reseal, and no key escrowed anywhere.
- Matches the owner's 2026-10-15 lean towards shipping all slices together (ROLLOUT_PLAN, release mechanics).
- Stages 0 and 1 can ship earlier: stage 1 through Bug 92's export passphrase.

**B. Silent reseal first.** Key slots and device slots let every install reseal in an earlier release. Phrases
come in a later one.
- The riskiest operation ships and runs alone.
- Graduation then needs a rekey, a second reseal (§1.1).
- About 2–3 more weeks than A.

**Open, needs a decision,** together with which release carries the work. Since 2026-10-16 that no longer
depends on the prekey refactor.

### 7.2 Stages, for order A

| # | Stage | Ships | Weeks |
|---|---|---|---|
| 0 | Groundwork | The reseal's reads fail loudly (C1); a key cache that drops on device lock (C2); a `VersionedSchema` baseline (register §G); new-store-file mechanics (Bug 168's proposal); the "data survives" reseal test (C3); PBKDF2 and Enclave timing on an iPhone 11; generator v2 (§2.3) | 1.5–2 |
| 1 | Keyboard and learning ladder | §2.2, §2.5. Can ship first on Bug 92's export passphrase | 1–1.5, alongside 0 |
| 2 | Close the design | §8, plus the spec's own open items: padding range, blob sizes, depth creation across images, the model sweep for requirement 5 | 1–2 |
| 3 | Key derivation, headers, chain, shared key; vault into the new store | Spec §1 and §2 (2026-10-15); row AAD (step 5) | 2–3 |
| 4 | Contacts into the new store | One padded blob per contact; groups per depth; origin lists; padding rows; stamps dropped; prekey blobs (D9); the ~175 sites in §4 | 4–7 |
| 5 | Remaining records | Backup keys, custody shards, restore records; the Bug 141 queue and Bug 162's open part (ROLLOUT_PLAN stage 4) | 1–2 |
| 6 | Phrase setup and the phrase lock screen | Every row of §3.1; the old-PIN fallback (§1.2); the coercion gate without absolute depths (§1.3); adding and removing depths; graduation | 2.5–4 |
| 7 | Copy and test period | Steps 11 and 16 through counsel; TestFlight on phones with several depths | 1, plus ~3 calendar weeks: the probation week and a 7-day phased release |

**Total: about 13–21 weeks of build, roughly 3–5 months.** Stage 4 and stage 2 decide where in that range it
lands.

---

## 8. Open, needs a decision

The spec's own 2026-10-15 items stay open there and aren't repeated here.

1. **Key slots,** or rows directly under `layerKey_D` (§1.1).
2. **Release order A or B,** and which release carries the work (§7.1).
3. **Rule 4's way back** through the old store (§1.2).
4. **Installs with no lock** (§1.4).
5. **The coercion gate** under phrases, lowering it at the real depth, and depths a coercer created (§1.3).
6. **Phrase setup seen from a duress depth**, and from a depth with the gate lowered (§3.1).
7. **Removing a depth,** and how it shows across images (§5).
8. **The wordlist**: full list or a short-prefix subset (§2.4).
9. **VoiceOver and the suggestion bar** (§2.5).
10. **Rehearsal reminders** after graduation (§2.5).
11. **A setup deadline** for lock users without a phrase (§3.2).
12. **Vault Face ID** once depth keys replace the vault key (§6).
13. **A test phone with no real data.** Which one?

---

## Related tracked items

[`bugs.md`](../Features/Secure%20Mode/bugs.md) and the register stay canonical. These are the items this plan
depends on or changes.

| Item | Summary | Status | Here |
|---|---|---|---|
| Bug 37 | Re-enable PIN fails silently at a lowered gate with an unknown PIN | Closed (fixed) | §1.3: the fix has no phrase equivalent yet |
| Bug 62 | `pinCollision` PIN oracle | Open | Gone with the old store at graduation (§3.2) |
| Bug 92 | Exported backup opens with the backup key alone; opt-in export passphrase unbuilt | Open, re-scoped 2026-09-24 | §6: shares the keyboard |
| Bug 109 | Per-depth keys leave an authentication-failure tell | Closed moot, 2026-09-10; spec §2 (2026-10-15) argues an all-or-nothing row isn't this tell | §4, §5 |
| Bug 119 | Vault key is device-level; one key opens every depth | Open | The whole plan |
| Bug 120 | Write frequency across images shows the real depth | Open; can't be closed with per-depth keys against a surrendered phrase, needs a decision (2026-10-15) | §5 |
| Bug 123 | Small sealed fields share one AAD | Closed, subsumed into 119 | Stage 3 (step 5) |
| Bug 138 | A migration destroyed the only copy before saving the replacement | Fixed 2026-09-26 | §1.2: the old store survives until graduation |
| Bug 139 | Keys from an interrupted rotation never deleted | Fixed 2026-09-26 (wipe) | The reseal's rule: interruption leaves nothing |
| Bug 141 | Depth-blind owner queue and watch rows | Fixed 2026-09-27; sealing per depth open | Stage 5 |
| Bug 148 | A file opened from outside shows before the PIN screen | Fixed 2026-09-28 | A file arriving behind the lock must still wait, and with phrases it also has no key to open with |
| Bug 162 | A trustee's piece count shows how many depths have a backup | On-screen count and manifest size fixed (PR #114); stored rows and piece dates open, needs a decision | Stage 5 |
| Bug 168 | A downgrade migrates the store back and drops what the older schema lacks | Accepted 2026-10-16 for the prekey records; a new store file for the passphrase migration proposed, not decided | §1.2, stage 0 |
| Register C1 | Decryption failure not representable | Open, P1 | Stage 0 |
| Register C2 | Local DB key re-derived per operation; no cache | Open, P1 | Stage 0 |
| Register C3 | No key-manager seam; no "data survives" reseal test | Open, P1, as recorded. The seam now exists (`Manager.Ambient`, `TestKeyManager`); the test doesn't | Stage 0 |
| Register §G | No `VersionedSchema` | Open | Stage 0 |

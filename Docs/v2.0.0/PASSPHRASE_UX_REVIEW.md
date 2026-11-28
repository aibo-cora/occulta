# v2.1.0 — Passphrase Rollout: UX Review

**Status:** Review, 2026-11-24. Nothing here is decided. It changes no design document and no code; the owner
chooses which findings to adopt. Written against `PASSPHRASE_ROLLOUT.md` as of `e547de7b`, with
`PASSPHRASE_LAYER_KEYS.md`, the passphrase entries in `decisions.md`, and the screens the plan replaces:
`PINEntry`, `SecureModeSetupFlow`, `SecureModeDeactivateFlow`, `Settings` (Security, Erase All Data), `AppScreen`,
`OnboardingView` and `Manager.PassphraseGenerator`. `Friction/` was read; it is about pairing and adoption and says
nothing on the lock, so it bears on this only through finding 4 (people turning the lock off).

The path name says v2.0.0 because the rollout plan lives there; the release is 2.1.0.

**How to read it.** Each finding gives the flow and step, what the person experiences, a severity, a suggestion,
and a **threat check**: the depth-only observables the suggestion touches (timing, copy, layout, settings, counts,
errors) and whether it leaks to a coercer holding the phone unlocked at a duress space, or to a forensic examiner.
Where a suggestion leaves a residual, it is labelled *open, needs a decision*. §D lists what I considered and
rejected because it leaks.

Severity: **Critical** is irreversible loss of data, or the coercion defence failing, for an ordinary user on an
ordinary path. **High** is a flow most people will hit that goes wrong or defeats the design's own aim. **Medium**
is real friction, or a gap that has to be settled before stage 6. **Low** is copy and polish.

**Publication check (the repo is public).** The findings concern the *planned* design and its UX. None describes a
mechanism of an unfixed vulnerability in a shipped build; where a finding touches a numbered bug, it cites only
what the rollout document already states. No push or PR has been made; that is the owner's call.

---

## A. Summary

| # | Finding | Flow | Severity | Rollout § |
|---|---|---|---|---|
| 1 | Forced, one-sitting memorisation of K+1 phrases, then the old store is deleted: no way back, and a recall check made minutes earlier | Migration; first weeks | **Critical** as written; the forced part is removed by opting in (§F) | §3.1, §3.2, §2.5, §1.2, §8 (4, 10) |
| 2 | A wrong phrase opens an empty app, silently; nothing says "this may be a slip" | Daily unlock; stress | **High** | §1.5 (no typo check), §8 (28) |
| 3 | The decoy phrase is the one most needed under coercion and the least practised; rehearsal was dropped on a premise that misses this | First weeks; coercion | **High** | §2.5, §8 (14) |
| 4 | 37 blind taps, no biometric, a 5-minute grace and no "Lock now": people will turn the lock off | Daily unlock | **High** | §2.2, §8 (27), Rule 3 |
| 5 | The keyboard leaks the prefix through disabled keys, commits words invisibly, and can't be corrected | Typing; stress; a11y | **High** | §2.2 |
| 6 | There is no way to switch space except waiting out the grace or killing the app | Another space | **High** | §1.3 (7c), §1.5 |
| 7 | "Add a space" is not specified, and the decoy's content model changed under the old copy | Another space | **High** | §1.5, §5, §7.2 stage 6 |
| 8 | The phrase screen is the one moment the words are shown in full, and it is unprotected from capture | First setup | **High** | §2.2, §2.5 |
| 9 | Erase All Data keeps its name and loses most of its meaning | Erasing a space | **High** | §5, §6, §8 (25) |
| 10 | Lock off and on is not a toggle: every lock-on is a new 7 words | Daily; coercion | Medium | §1.3, §8 (25) |
| 11 | The mixed PIN-and-phrase window and an unfinishable Rule 2 | Migration | Medium | §3.1 (8a, 8b), §3.3 |
| 12 | Forgetting the phrase: the lock screen has no help, and the copy isn't written | Forgetting | Medium | §6 (Recovery), spec §4 |
| 13 | Accessibility | All | Medium | §2.2 (13a, 13b) |
| 14 | English words for people who don't read English | First weeks; a11y | Medium | §2.1–§2.3 |
| 15 | A file for another space must not be consumed by the "deleted or cannot be found" screen | Another space | Medium | §1.5, §8 (24) |
| 16 | Old copy now says things that are false | All | Low | §6, Onboarding, Settings, Setup flow |
| 17 | Generator and display details | First setup | Low | §2.3 |

Four decisions would settle most of the severe ones: **1** (a deferral and when the old store goes), **6 and 7**
(how a space is added and reached), **5** (the keyboard's commit and feedback rules) and **3** (what, if anything,
replaces rehearsal).

---

## B. What the design gets right, which suggestions have to keep

These are the properties a UX change must not weaken.

1. **Any phrase opens something.** A typed phrase that matches no space opens an empty one (§1.5). This is what
   lets a coerced person hand over *any* phrase and be unable to be caught out: the coercer can't tell "a decoy
   with nothing in it" from "a made-up phrase". It is the design's best deniability feature and it is **fragile**:
   any UI that says "not recognised", "no space uses this", or "first time you've used this phrase" removes it
   (§D, items 1 and 2).
2. **One lock screen, one setup, one set of Settings.** Same words, layout and timing at every space and on every
   install (§1.3's governing rule, Rule 3).
3. **The app keeps no list or count of spaces** (§1.5, §5), so no screen can name, count or offer another one.
4. **The phrase is app-generated and never stored** (decision 12; spec §3). Nothing can re-show it.
5. **No lockout state.** There is no "wrong attempt", so there is no counter to see (§1.5).
6. **No per-tap visual feedback** (decision 13a) and **no suggestion bar**: the camera and shoulder-surfer concern
   is right, and finding 5 is about two places where the keyboard breaks it anyway.

Findings 2, 3 and 7 are shaped by item 1.

---

## C. Findings

### 1. Forced one-sitting memorisation, then no way back — **Critical**

**Flow and step.** Migrating from a PIN, first unlock after the update (§3.1, §3.2, decision 10), then the first
weeks (§2.5).

**What happens.** At the first unlock after the update the person can't use the app until the ladder is passed
(§3.2: "no 'Later'"). For a PIN-only install that is 7 words. For Secure Mode with K duress layers it is **K+1
phrases in one sitting** (Rule 2, §3.1): 14 words for one duress layer, 21 for two, each with its own four-step
ladder. When the reseal verifies, the old store is deleted (§1.2, §3.2), so there is no PIN to fall back on: a
phrase forgotten afterwards is that space's data gone for good. The only recall check is the ladder's last step,
typing the phrase unaided, a few minutes after seeing it.

**What the person experiences.**
- Three random 7-word lists learned back to back interfere with each other. Typing a list correctly five minutes
  after seeing it is short-term memory; it says almost nothing about next Tuesday. The ladder's other steps (fill 2
  gaps from 4, put the shuffled words in order) are recognition, which is easier still.
- The update installs itself, often overnight. The first unlock can be anywhere: at a checkpoint, in a meeting, with
  a coercer watching. The person is held at a four-step screen with a new phrase on display. (Under 8a a decoy gets
  exactly this, with the phone in someone else's hands.) A screen that takes minutes is itself noticeable, and the
  person is tempted to rush it.
- Existing Secure Mode users are the most security-conscious group and carry the largest load.
- The release note says setup is required; it can't say when it will happen.

**Why it is Critical.** Forced, irreversible and hurried, on the install base with the most to lose. It is the one
step where a UX failure destroys data.

**Decided 2026-11-28 (owner): the phrase is opt-in** (§F, items 1–4). People with a PIN are offered it once, with
Migrate Now, Remind me Later and Dismiss, and it stays in Settings; no one is held at the ladder on first unlock. That removes the bad-moment
problem, so suggestion 1 (a deferral) is **not needed** and suggestions 2–5 apply to whoever opts in. The text
above describes the forced version and is kept as written for the record.

**Suggestions** (independent; the first two mattered most before opt-in).
1. **A deferral with a release-wide deadline.** Offer "Not now" at the first-unlock gate to everyone, at every
   space, until a date fixed in the code (say 14 days after the release ships). After that date the gate is
   mandatory. The only per-install state is that the old store still exists, which an image already shows today.
   This keeps decision 10's aim (nobody marks themselves by setting up early: the date is the same for all, and
   "Not now" writes nothing) and removes the bad-moment problem. Cost: the old PIN path stays in code for that
   window; the plan wanted it gone at once.
2. **Don't delete the old store at reseal verification; delete it at the first cold-launch unlock after setup that
   opens a space with content in it,** with the same release-wide date as a backstop. This is a narrower thing than
   the probation week decision 4 dropped: no ring, no per-space progress record, nothing stored in the new store.
   The state is again just "the old store still exists". It turns the dangerous case (the real phrase forgotten
   within a day) into a recoverable one, at the price of the old store lasting a little longer than "verified".
   *Decided 2026-11-28: adopted, with no release-wide date* (there is no deferral under opt-in, so no backstop). The
   price is the exposure window decision 4 weighed: until that first cold unlock the old data is as readable as it
   is today. With duress layers the first cold unlock may be with a decoy phrase, which proves only that phrase.
   That is no worse than decision 4 as written.
3. **Keep the ladder's last step as the only check, and don't tell people how to store the phrase.** An earlier
   draft added "write it down and type it back from the paper"; withdrawn. A paper copy is a trace of its own, and
   so is an entry in the phone's own password manager, which sits on the phone a coercer holds and syncs to the
   cloud. The app can't tell the real phrase from a decoy, so one piece of copy has to be right for both (finding
   12, suggestion 3). This makes suggestions 1 and 2 more important, not less: with no advised copy, a forgotten
   phrase has no fallback.
4. **Say what is and isn't final.** The phrase is final only when the reseal verifies; abandoning the ladder
   before that writes nothing and shows a *new* phrase next time. After an interrupted reseal the person must
   retype every phrase (the keys come from them); say so on the resume screen, so they know to expect it.
5. **For K ≥ 1, say up front how many phrases there are and roughly how long it takes,** and let the person leave
   the flow and start over rather than rush it (with suggestion 1 that costs nothing, since nothing is written
   until the reseal). Rule 2 means the phrases can't be split across sittings; the other levers are above.

**Threat check.** Suggestion 1: the observable is the old store's presence and the date constant, both the same
for every space and install; the prompt looks the same at a decoy and at the real space. Suggestion 2: same state;
residual is the old store's window, decided 2026-11-28 (above). Suggestions 3–5 are local to a screen shown
identically everywhere. Nothing here depends on or reveals a space count.

---

### 2. A wrong phrase opens an empty app — **High**

**Flow and step.** Daily unlock; typing under stress; the first weeks. §1.5 ("a mistyped phrase opens an empty
space, and the app can't tell it from a new one").

**What the person experiences.** The lock screen has no "wrong" state. A slipped word, a misremembered word, or
the previous phrase typed by habit (finding 10) all end the same way: about a second of derivation, then an empty
contact list, no error. The first reaction is "my data is gone". The next is to add a contact or a note, which
writes into a space nobody meant to create. There is no feedback of any kind before that first write. Compared
with today's PIN, where a wrong entry shakes and clears, this is a large step down in how safe a slip feels. The
keyboard makes slips likelier (finding 5), and the submit is automatic after the 7th word.

**Note on the premise.** §1.5 says the app can't tell a typo from a new space. Since decision 28 (a manifest row
per space) it technically can. That is a trap: using it is exactly the "not recognised" message that removes the
safe bluff (§B, item 1), so I recommend **not** using it (§D, item 1). The fix has to be elsewhere.

**Suggestions.**
1. **Don't submit on the 7th word.** Show the dots, and require an explicit "Unlock" tap. One extra tap; a last
   word that was mis-tapped can be removed first (finding 5 makes backspace remove a whole word). *Decided
   2026-11-28: adopted.*
2. **One empty-state for every empty space,** the same whether the emptiness is a decoy the user made, a slip, a
   space the user erased or a fresh install: "Nothing here yet." On top of it, only when the space was reached by
   typing a phrase, a dismissible line: "If you expected your contacts, lock the app and try again." It is never
   shown on a lock-off install, which has no phrase screen (the Bug 223 test requires Settings to show nothing of
   a phrase there), so it can't hint that a phrase exists where none is set.
3. **Make a stray space cheap to leave.** The first write into an empty space goes through with no interruption
   (a prompt would be the oracle of §D, item 2). Instead make Lock now (finding 6) easy to reach, so a person who
   sees an empty app can back out before writing.

**Threat check.** The unlock timing is the same for every phrase (derivation plus the trial open of every row
runs whatever the outcome, as today's 0.5 s pad does for the PIN; keep a floor). The empty-state copy is the same
in every empty space, on every install; the line shown after a typed phrase is the same whether the space is a
real decoy or a slip. It tells a coercer the app supports phrases, which onboarding already says. No manifest
check is read by the UI. Residual: a person who writes into a stray space still has data they can't find.
*Decided 2026-11-28:* accepted. No first-write notice (it would be the verifier of §D, item 2), and suggestions 2 and
3 are adopted: a uniform empty state with the dismissible hint after a typed phrase, and no prompt on the first write.

---

### 3. The decoy phrase is the least practised and the most needed — **High**

**Flow and step.** First weeks, then coercion. §2.5 (rehearsal not built), §8 (14).

**What happens.** Decision 14's reasoning is that a duress phrase "is typed rarely, and forgetting it loses only
decoy content". That is true of the data and misses the point of the phrase. Under coercion the person has to
*produce* it, quickly, in front of someone who is watching. Forgotten or hesitated over, the coercer is looking at
the real thing failing, and the next step is to ask for another. Two failure modes follow:
- **Forgetting it altogether.** Seven random words for a space opened a handful of times.
- **A behavioural tell.** The real phrase is typed daily, at speed; the decoy is typed haltingly, with pauses at
  words the person isn't sure of. That is observable without any app help.

**What would a fix need.** A practice that tells the person "that opened a space" is a verifier, which is the
oracle of §D, item 2. So practice can't verify through the manifest and stay bluff-safe.

**Suggestions.**
1. **Make the decoy self-verifying by giving it recognisable content,** and say so at setup: "Put a contact or a
   note in this space, so you can tell it opened." A decoy with something in it also answers the "I deleted
   everything" problem (finding 7). This is copy and flow, not state.
2. **Switch on purpose** (finding 6): a visible Lock now means a person can open the decoy deliberately, weekly,
   as practice. That is the only verification that isn't an oracle: they recognise their own decoy content.
3. **A second timed round in the ladder for every phrase after setup** (type it, wait ~2 minutes doing the next
   phrase, type it again). Cheap; no stored state.
4. *Not recommended:* a stored "last practised" per space, a reminder, or a Settings "check my phrase". Notifications
   are forbidden by `OSTraceTests`, a per-space date is a per-space record (§1.5), and a checker is the oracle.

**Threat check.** 1 and 2 are copy and an existing-style control, the same on every install. Residual: a decoy
that is empty stays unverifiable by its owner. *Decided 2026-11-28:* add suggestion 1's copy at setup, the same for
every phrase, and take that residual as the price of keeping the bluff.

---

### 4. The cost of daily unlock will drive people to turn the lock off — **High**

**Flow and step.** Daily unlock. §2.1–§2.2, §8 (27), Rule 3.

**What happens.** A cold launch, or 5 minutes in the background, asks for 37 taps (§2.1) with no feedback, against
6 digits today, with no biometric shortcut (spec §4 rules out wrapped Face ID re-entry). Someone who opens the app
10 to 20 times a day taps roughly 370 to 740 times. The spec itself predicts the result: "Many will turn the lock off, and
the people still using one become the signal rule 3 is there to avoid." Lock off puts the key under a device-only
key (§1.3, 7a), no better than the iPhone passcode. So a design whose strength is a 7-word phrase ends up with
most people at the weak end, and the few at the strong end are easier to pick out.

**Suggestions.**
1. **A grace setting, same choices everywhere** (for example 5 min, 15 min, 1 h), default 5, with honest copy:
   what a longer grace leaves open is already stated in §8, item 27 ("someone who takes the phone unlocked, or
   compels its passcode, within [the grace] opens the space last open"). It is install-wide, so it isn't a
   per-space value.
2. **Lock now** (finding 6), so a longer grace is safe to choose: the person locks when they put the phone down.
3. **Keep the tap count honest:** the suggestion in finding 5 (a "next word" key) costs 7 taps and is worth it;
   everything else that adds taps (a confirm step, an "are you sure") should be questioned. Accept a hardware
   keyboard when one is attached (finding 13).
4. **Copy at lock-off:** say plainly that it is as strong as the phone's own passcode, which §1.3's one warning
   already does; add that turning it back on means a new phrase (finding 10).

**Threat check.** The grace value is one install-wide setting, visible only when a lock is on (which the lock
screen already shows). It is not stored per space and not a depth number, so it names nothing. Residual: a longer
grace widens the stated window of item 27. *Decided 2026-11-28:* the grace stays fixed at 5 minutes, with no
setting (suggestion 1 is not adopted); Lock now and the padlock (finding 6) cover people who want a shorter
window. Opting in is for people who foresee coercion, which lowers the worry that the tap cost drives people to
turn the lock off. Revisit only if testing shows they do.

---

### 5. The keyboard leaks, mis-commits and can't be corrected — **High**

**Flow and step.** Typing the phrase, at setup and every unlock. §2.2, §2.1.

Five separate defects in one component.

**5a. Disabled keys are a suggestion bar by another name** (security). §2.2 disables "letters that can't continue
any list word", and §2.2 also says no suggestion bar because "whole words on screen are easier to read from a
distance or on CCTV". A key that greys out changes the keyboard's appearance after every tap. After three letters
the enabled set is small (median 12 words share 3 letters). Anyone filming the keyboard, not the finger, reads the
possible next letters, and the pattern across words narrows the phrase. It also contradicts "no visual feedback on
a tap". *Suggestion:* the keyboard never changes how it looks. An invalid letter is simply refused, with a
distinct haptic (and the VoiceOver sound of finding 13). Cost: nothing on screen says why a key did nothing; the
haptic does.

**5b. Words commit invisibly, so people overshoot into the next word.** A word commits as soon as its prefix is
unique, 5.3 letters on average, "with no confirm step". A person who types the word they remember ("acorn") has
already committed it at "aco" and the "rn" goes to the next word. The only cue is the haptic and a dot filling.
They then can't tell what is typed; the phrase is garbage; the result is finding 2. People will spell whole words:
the learning screens show whole words, and diceware habit is to type them. *Suggestion:* a **"next word" key**
(a space bar). A word is accepted when the person presses it, as soon as the prefix is unique, so typing the whole
word works and typing only the prefix works. Cost: 7 more taps (44, not 37). Visual: a dot fills on the key press,
not before. Alternative if the owner prefers 37 taps: keep auto-commit but make the commit unmistakable (a
distinct, stronger haptic and a dot animation), and teach the "shortest unique prefix" explicitly in the ladder.
I think the first is kinder; it is a decision.

**5c. "So a typo can't happen" is an overclaim** (§2.2). A letter that continues *some* list word is accepted: at the
4th letter of a word a mis-tap to a neighbouring valid letter is silently a different word. The keyboard prevents
impossible prefixes, not slips. The copy and the setup tour shouldn't promise otherwise.

**5d. Backspace, cancel and review are undefined.** Does backspace remove the last letter of the current word, or
the last committed word, or nothing once a word has committed? Is there a "clear all"? Can the person check what
they typed before submitting? Under stress these matter more than anything else on the screen. *Suggestion:*
backspace removes a letter within a word and a whole word at a word boundary; a clear-all; press-and-hold the dots to
reveal (as §2.2 has) with an accessibility action for the same (finding 13); explicit Unlock (finding 2).

**5e. No indicator of the partial word.** Committed words are dots, and the letters of the current word show
nothing, so after an interruption there is no way to know whether 2 or 4 letters are in. *Suggestion:* a small
count of letters in the current word (a growing tick), not the letters. It reveals the prefix *length*, which the
tap rhythm already shows.

**5f. Haptics-off leaves no feedback at all.** `UIFeedbackGenerator` follows the System Haptics setting. With it
off, or on a device that can't, a tap gives nothing. *Suggestion:* an install-wide "Show what I type" setting off by
default (letters in the dots' place) for people for whom the trade is right, same at every space.

**Threat check.** 5a *closes* a leak. 5b's key adds only the word count, which the dots show. 5c–5e: local to the
keyboard, identical at every space. 5f is a user-chosen install-wide setting. Tap timing and tap count are
observable by a camera in every design; none of these adds a depth-only signal.

---

### 6. No way to switch space — **High**

**Flow and step.** Adding and using another space. §1.3 ("other spaces are reached from the lock screen"), §1.5.

**What happens.** The lock screen appears on a cold launch or after 5 minutes in the background
(`AppScreen.gracePeriod`). There is **no manual lock** in the app today and none in the plan. So a person in the
real space who wants the decoy, or the reverse, must kill the app or wait out the grace. That's two problems:
- *Switching:* clumsy and slow; people will force-quit, which is itself a pattern.
- *Handing over the phone:* the person leaves the real space and the phone is taken a minute later; within the
  grace it opens (§8, item 27's stated residual). With no Lock now there is no way to close it.

**Suggestions.**
1. **A Lock now control**, always in the same place (Settings > Security, the owner's choice), shown
   when the lock is on. It drops the key and every decrypted record, ends the grace and shows the lock screen, as
   going past the grace does (§8, item 27). It is both the switching mechanism and the "put the phone down"
   mechanism.
2. **A visible button, not a hidden gesture.** A hidden gesture is a tell if discovered and a trap for the person
   who forgets it.
3. The lock screen after Lock now is the same screen as after a cold launch.
4. **Call it "Lock now", and let it double as the way to switch.** Switching is Lock now followed by typing the
   other phrase. Typing is the rehearsal that finding 3 needs, so the switch must not be made cheaper than that.
   **Not "Switch space" or "Switch account".** Either word tells whoever opens Settings that a second space exists,
   on every install with the lock on, and an app with no sign-in has no accounts to switch; the familiarity of
   "Switch account" is the leak. Only a lock is neutral. An earlier draft of this suggestion used "Lock / Switch
   space"; it had the same flaw and is withdrawn. *Decided 2026-11-28: the owner asked for "Switch Account" and,
   after the trade-off was put to them, chose "Lock now".*
5. **Rejected 2026-11-28 (owner): flip between spaces opened in this session.** Once a second phrase has been typed, the first
   space's key stays in memory and a toggle appears, so the two feel like switched accounts. Nothing is written
   to disk. Lock now, grace expiry and an app kill clear every cached key. The toggle is absent until a second
   phrase has been typed this session, its rows carry no names or colours, and it exists only in memory.

**Threat check.** The control exists on every install with the lock on and is absent on installs with it off,
which the lock screen already shows. It is not per space and names nothing. A coercer sees a lock button; that
tells them there is a lock. Pressing it in front of them is ordinary.

**Placement.** In Settings > Security the control is three taps away. That suits switching and is slow for
"someone is walking up". *Decided 2026-11-28: adopted.* An icon-only padlock in the top bar of every tab is a second
route. It names nothing, it is not per space, and it is the same on every install with the lock on.

**Why not a stored switcher** ("the real space has access to all the others", as with account switching). It
needs the other spaces' keys or phrases kept inside one space, so:
- *List and count.* Whoever has that one phrase, by coercion or by watching it typed, learns how many spaces there
  are and can open every one. Independence is lost: today handing over one phrase reveals nothing about the rest.
  The app does not know which space is "real", so a person with several compartments has no obvious top.
- *Depth-only observable.* A switcher in one space only marks that depth; one in every space needs invented
  entries in the others, and the shapes then differ.
- *A stored trace.* Wrapped keys inside a space are a persistent artifact, and "phrases are never stored" stops
  being true.
- *It erodes finding 3.* A one-tap switch means the decoy phrase is never typed, then forgotten, then unavailable
  under coercion.

**Decided 2026-11-28 (suggestion 5): rejected.** Someone who takes the unlocked phone mid-session, after both
phrases were typed, would see the toggle and learn a second space exists. Suggestion 4 alone has no such leak, and
switching stays "type the other phrase", which is also the practice finding 3 needs.

---

### 7. "Add a space" is not specified — **High**

**Flow and step.** Adding and using another space. §1.5, §5, §7.2 stage 6 ("phrase setup, the phrase lock
screen"). Stage 6 lists setup and the lock screen and Erase, but never how a second space is made.

**What's missing.**
- **Where and how it is created.** Phrases are app-generated, never chosen (decision 12), so a space can't be
  created by typing a phrase at the lock screen: a person could type "abacus abacus…" and own a space with no
  entropy. So there has to be an action, from inside an existing space, that generates a phrase, shows it, runs
  the ladder, and writes the new space (including its manifest row, §8, 28). None is described.
- **What the person sees in the new space.** An empty app. The old flow let them pick which contacts the decoy
  showed (`ContactClassification`); under §8, item 29 there is no copying, so a decoy starts empty, and the cover
  story is "I deleted everything".
- **How a decoy gets content.** It needs a contact or a note to be believable and, per finding 3, recognisable.
  Contacts are made by in-person pairing (U1 phones) or manually. Both need to work inside a fresh space, and
  the person needs to be told.
- **What the Settings entry reads.** The same at every space and install.

**What the person experiences without it.** They can't find how to make the decoy. If they type a made-up phrase
into the lock screen they will get an empty space, and believe they have set up protection, with a phrase that is
unverified, unwritten and weak.

**Suggestions.**
1. **Specify it as "Add another space" in Settings → Security, shown on every install with the lock on,** with the
   same flow as first setup (generate, show, ladder, write). Be explicit that typing an unknown phrase at the lock
   screen does *not* create a space in the sense of protection; it just opens an empty one.
2. **State the decoy's purpose in setup:** "Put something in it so you can tell it opened (finding 3), and so it
   looks used."
3. **Make a manual contact easy in a fresh space** (no pairing needed), since a decoy can't rely on two phones.
4. **Mirror the single-space setup's cost in the copy:** another 7 words to learn.

**Threat check.** The Settings entry is the same on every lock-on install, at every space. A coercer at a decoy sees
"Add another space", which says the feature exists (as onboarding already does) and nothing about whether another
space is there. The flow writes a manifest row and rows like any write (within Bug 120's stated limit, §5). The
copy must be written once for all spaces and not say "your other space" anywhere.

---

### 8. The phrase screen is open to capture — **High**

**Flow and step.** First setup and each added space. §2.2, §2.5.

**What happens.** The phrase is displayed whole, once, on a screen. §2.2 deals with the *app-switcher snapshot*
and "state restoration"; it doesn't mention the other ways a screen leaves the phone:
- **A screenshot,** which goes to Photos and, with iCloud Photos on, to the cloud and to every device on the
  account. That is the phrase *and* a forensic artefact (`CLAUDE.md`, Architecture: forensic trace clean).
- **Screen recording or mirroring** (`UIScreen.isCaptured`, AirPlay, a QuickTime cable).
- **A bystander.**

**Suggestions.**
1. **Hide the words while the screen is being captured or mirrored,** and blank the screen when a capture starts.
2. **On a screenshot (`userDidTakeScreenshotNotification`), say so,** with the steps to remove it (Photos, then
   Recently Deleted), and offer to generate a new phrase now (nothing has been written yet).
3. **Say that a screenshot is not a copy to keep:** it sits in the Photos library and in iCloud. Name no storage
   method (finding 1, suggestion 3).
4. **A "Cover the words" button** that the person can use when someone walks in.

**Threat check.** These run only on the phrase-display screen, which is the same at every space. They add no
observable at the lock screen or in Settings. A coercer watching the setup sees the same screen as everyone.

---

### 9. Erase All Data keeps its name and loses its meaning — **High**

**Flow and step.** Erasing a space. §5 ("Erase All Data erases the current space only"), §6, §8 (25), stage 6.

**What happens.** Today the button wipes everything, and its copy says so ("Delete **entire** contact database,
vault, private keys and stored messages"). After 2.1.0 it shreds the current space's rows and leaves the identity
key, the tier secrets and the Enclave keys (§5). A person who taps it in the real space before travelling, or after
a theft, believes the phone is clean. It isn't: other spaces stay, the keys stay, and the phrase still opens the
(now empty) space. §5 says there is no in-app full wipe and that the copy "says so", but the copy isn't written, and
its wording is hard: the label can't say "this space" or "other spaces" without mentioning them.

**Suggestions.**
1. **Rename it for what it does, not for what it used to do:** "Erase what's in Occulta" or "Erase this data". Don't
   call it "All".
2. **Describe it by what the person can see,** not by spaces: "Deletes the contacts, vault and messages you can
   see right now. Keys that belong to this iPhone stay on it; resetting the iPhone removes them. Your phrase will
   still open Occulta." The same words at every space and on every install (including single-space and lock-off
   installs, where "your phrase" is replaced by nothing: write two strings that differ only in that clause, chosen
   by whether a lock is on, which the screen already shows).
3. **After erase, show the empty state of finding 2** and say the phrase still opens it.
4. **Say how to wipe everything:** the iPhone's own reset. A one-line link, not a flow.
5. **Don't offer an "erase on N wrong tries"**: there is no wrong try (§B, item 5).

**Threat check.** The copy is the same everywhere, names no other space, and makes the same claim at a decoy and at
the real space. Erasing leaves an empty space, which looks like any other empty space; the shred is invisible (§5).
Item 25 already puts Erase's group-write in the stated limit.

---

### 10. Lock off and on is not a toggle — **Medium**

**Flow and step.** Daily use; coercion. §1.3 (7a, 7c), §8 (25).

Today "Enable PIN" is a toggle and people flip it. Under 7c, turning the lock on *always generates a new phrase and
reseals the space*, and refusing the old phrase is deliberate (§1.3: accepting it would leave earlier images
openable). So:
- **Off and on again is another 7 words and a ladder,** plus a whole-space rewrite with its progress time.
- **Habit trap.** After re-locking, the old phrase typed by habit opens an *empty space* (finding 2). The first
  report will be "I turned the lock back on and lost everything".
- **Lock off makes the other spaces unreachable** until it is turned on again (§1.3): someone coerced into turning
  it off at the decoy can't get back to the real space without turning it on, and that gives the decoy a new phrase
  they have to learn in private.

**Suggestions.**
1. Present it as **two actions, not a switch:** "Remove the lock" and "Set a new phrase", each with its cost stated
   ("The old phrase will stop working", "You will learn 7 new words").
2. Say after re-lock that **the previous phrase now opens an empty space.**
3. Show **progress and don't allow cancellation mid-write** during the reseal; the time depends on the space size.
4. Lock-off warning stays the one warning of §1.3.

**Threat check.** The same actions and words at every space and install; the lock state is visible already. The
"previous phrase opens an empty space" line is the design's own property, not a depth fact.

---

### 11. The mixed window and an unfinishable Rule 2 — **Medium**

**Flow and step.** Migration with 8a or 8b. §3.1, §3.3.

- **Two kinds of lock screen at once.** In 8a the decoy has migrated and the old store still opens with the PINs
  until every layer has. The lock screen has to accept a 6-digit PIN *and* a word phrase. A single screen with both
  needs a way to switch between keypad and word keys; that control is a visible sign that a PIN path exists, for the
  length of the window. The plan doesn't say how this screen works. It should decide, and keep the window short
  (finding 1, suggestion 1).
- **Rule 2 can't always be met.** In the 8a window the real user must type the decoy's phrase again, which they
  last saw under coercion. If they can't, the old store (with all the data) stays for as long as the layer isn't
  migrated, "waits for the others" (§3.1). A person who has forgotten it has no exit. *Suggestion:* a "I don't
  remember it: drop that layer" choice in the migration flow, same for everyone, with copy that says what is lost
  (a decoy's data). Dropping a decoy loses little by the plan's own account.
- **Interrupted reseal** needs the phrases again (finding 1, suggestion 4).

**Threat check.** The migration screens exist for everyone who has a lock; the drop-a-layer choice is in the flow
at every depth. Residual: a short window where the old and new paths coexist, within today's exposure (§3.1).

---

### 12. Forgetting the phrase — **Medium**

**Flow and step.** The lock screen after a forgotten phrase. Spec §4 ("Recovery"), §6.

The spec says forgetting is permanent and "needs explicit setup-time UX". Setup copy is planned (steps 11 and 16).
**The lock screen itself has nothing:** no help, no explanation, only keys. A person who has forgotten a word types
guesses, each opening an empty space, and learns nothing. There is no "Forgot your phrase?".

**Suggestions.**
1. **"Forgot your phrase?" on every lock screen,** the same everywhere: what can and can't be recovered (a Shamir
   backup restores the vault only, §6; nothing restores contacts), and that the only way to start again is to
   delete the app and re-pair contacts in person.
2. **Say it while setting up,** in the order: nothing can recover this; learn it, and if you keep a copy,
   keep it away from this phone (no method named); the phone's backup doesn't carry it (the Enclave key stays on this phone, and so does any
   space; a restore to a new phone starts empty: *Device Migration* is out of scope, §6).
3. **One rule for every phrase.** "Don't write the decoy down, do write the real one down" can't be said: the app
   doesn't know which phrase is which, and the copy must be the same for each. Use: "If you write it down, keep it
   where whoever might take your phone won't look."

**Threat check.** One help link on every lock screen on installs with a lock. It states a fact of the design, not a
depth fact. Counsel needs to review copy (step 11).

---

### 13. Accessibility — **Medium**

**§2.2** says VoiceOver behaves "as it does in iOS's own password fields" and that the setup screen suggests
headphones. `PINEntry` today has no accessibility labels at all; the new keyboard starts from zero.

| Need | Problem | Suggestion |
|---|---|---|
| **VoiceOver** | Keys are spoken as they are touched, aloud, to the room, at every unlock. A headphones suggestion on the setup screen isn't a control. | Check the audio route when VoiceOver is on: on the built-in speaker, show a notice on the lock screen (not a block). The person still needs the speech to find keys, so don't silence it. Haptic reject for invalid letters (finding 5a). |
| | Dots say nothing | Read "word 3 of 7 entered" on each commit (that leaks the count, which the dots show). |
| | The ladder's "put the shuffled words in order" is a drag | Give every row *Move up* and *Move down* accessibility actions, and a non-drag alternative for sighted motor-impaired users too. |
| **Dynamic Type** | Fixed-size keys and dots | Keys that scale to a limit, then a larger-keys layout (two rows more) at the largest sizes; the dots wrap. Test at AX5 and in landscape. |
| **Colour only** | A key's disabled state is colour (and 5a removes it); dot state is fill | Don't depend on colour; use shape for dots. |
| **Motor** | 26 small keys, 37 to 44 taps, no feedback | Wider keys; Touch Accommodations and hold duration respected (use a plain button, not a gesture recogniser); accept a **hardware keyboard** (a paired Bluetooth keyboard, as for passcodes); Switch Control and Voice Control labels per key. |
| **Haptics off** | No feedback | Finding 5f. |
| **Reduce Motion / Bold Text / Increase Contrast** | Shake and animation on the old PIN | No shake exists (no wrong state); keep animations to a minimum. |
| **RTL locales** | A row of 7 dots and a numbered list can mirror, and word order is the phrase | Force left-to-right for the dots and the ladder lists. |

**Threat check.** All local to the keyboard and ladder. The VoiceOver audio-route notice shows only when VoiceOver is
on. Nothing depends on the space.

---

### 14. English words for people who don't read English — **Medium**

**Flow and step.** First weeks; typing. §2.1–§2.3.

Seven English words from the EFF list for someone who doesn't know them is harder to memorise than 7 familiar
words, and the person is typing letters they can't check against meaning. They may recall a word by sound
("yelo" for "yellow"), and with the keyboard refusing the letters (finding 5a) they don't know why. The keys are
QWERTY while their own keyboard may be AZERTY or QWERTZ, or non-Latin. §2.2 says there is no paste and no system
keyboard, so any aid has to be in-app.

**Suggestions.**
1. **A "hear it" button on the setup and ladder screens** using system speech, with the headphones advice. Local;
   speech isn't stored.
2. **Layout follows the system's keyboard layout** (QWERTY, AZERTY, QWERTZ), or a one-time install-wide choice.
   A per-install layout setting names no space.
3. **Let the person reject a word they can't pronounce,** with a cap (two swaps per phrase) so the selection effect on
   the 90.5 bits stays small (at most about 5.2 bits in the worst case: 36 swap patterns over 7 positions).
   *Rejected 2026-11-28 (owner): no swaps.* Phrases are exactly as drawn.
4. **Don't translate the words on the lock screen.** A gloss in setup only would need a language pack per
   language; low value.

**Threat check.** Layout and speech are install-wide or screen-local. The swap cap is a generator rule, not a depth
fact.

---

### 15. A file for another space must not be consumed — **Medium**

**Flow and step.** Using another space. §1.5, §8 (24).

A file from a contact paired in the other space shows "The contact who sent this message was deleted or cannot be
found" (decided). For a person in the wrong space that is alarming and gives no way forward, and that's deliberate.
The UX risk is **what the app does with the file afterwards**: if the "not found" screen marks it consumed, or a
queued inbound file is dropped, then switching to the right space finds nothing. Also, if opening increments
anything (a prekey is consumed by a successful open only), it must not here.

**Suggestions.** The wrong-space refusal leaves the file in place and the queue entry intact; the file opens later in
the right space with Lock now (finding 6). No text on the screen about "another space".

**Threat check.** The screen is the decided one. Leaving the file in place is not visible in the UI; in an image the
staged file is data any space might have received.

---

### 16. Old copy that becomes false — **Low**

A sweep for stage 6 and the counsel pass (steps 11 and 16):
- `OnboardingView` `.secureMode`: "Set a second PIN. It opens Occulta with the contacts you choose, and your vault,
  hidden." There is no choice of contacts, and no second PIN (§8, 29). Footnote "Set it up in Settings › Security".
- `Settings`: the Security header "PIN protection and Secure Mode for this device." and the "Enable PIN" toggle.
- `SecureModeSetupFlow`: Education ("Hidden contacts: choose which contacts are visible"), the Contacts step
  (`ContactClassification`), Summary ("Secondary PIN set", "contacts will be hidden", the "ask each hidden contact to mark
  you as sensitive" note, "Vault will be cleared").
- `USER_GUIDE.md` (through counsel, §6).
- WhatsNew: tell people about the update and the setup before it happens (finding 1).

---

### 17. Generator and display — **Low**

- Show the 7 words in a numbered column, not a hyphen string, so the order is clear; the hyphenated export
  passphrase (Bug 92) can keep its format.
- Allow *Show new words* before the ladder starts (nothing is written until it passes): finding 14's cap.
- `Manager.PassphraseGenerator.generate(...)` doc comments are placeholders (`<#words description#>`); not a UX
  matter, but the new function will be the app's most-read generator.

---

## D. Considered and rejected, because they leak or break the design

1. **"Phrase not recognised" at the lock screen.** The manifest (§8, 28) makes it possible. It removes the safe bluff
   (§B, item 1): a coerced person handing over a made-up phrase is now visibly lying.
2. **A "check my phrase" practice screen, or a first-write notice "this is the first time this phrase has been
   used".** Each is a verifier. It tells a coercer holding the unlocked phone, and any phrase the user gave them,
   whether it opens a real space.
3. **A list, count or switcher of spaces,** a "you have N spaces" line, space names or colours. §1.5 forbids it.
   This includes a *stored* switcher in which one space holds the others' keys, like account switching (finding
   6, "Why not a stored switcher"). The in-memory toggle of finding 6, suggestion 5 was rejected on 2026-11-28 for the
   same reason: while it shows, it tells whoever holds the unlocked phone that a second space exists.
4. **A stored per-space date or reminder** (rehearsal, "last used"). A per-space record; notifications are forbidden
   (`OSTraceTests`).
5. **A per-space grace or setting.** Any value that differs by space is a depth-only observable.
6. **Wrapped-key Face ID re-entry.** Ruled out in spec §4.
7. **A visible suggestion bar, or autocompletion.** Ruled out by decision 13a; 5a is the same leak in a different
   place.
8. **A retype or checksum at setup** beyond the ladder's. Decided against (§1.5); the ladder's own last step
   (type it unaided, finding 1) is not a checksum.

---

## E. Order of decisions

1. **Finding 1**: ~~a release-wide deferral, and when the old store goes~~ decided 2026-11-28: opt-in, and the old
   store goes at the first cold unlock after setup (§F). The rollout's decisions 4 and 10 have to be rewritten to match
   before stage 6 can be finished.
2. **Findings 6 and 7**: Lock now; the "Add another space" flow. Stage 6's scope.
3. **Finding 5**: the commit rule (next-word key or stronger cue) and the disabled-key change. Stage 1's scope, and
   it can be tested on Bug 92's export passphrase first.
4. **Finding 3**: what replaces rehearsal; the answer is probably copy plus Lock now.
5. **Findings 4 and 9** are copy and one setting each.
6. The rest are for stages 1 and 6 and the counsel pass.

Nothing here changes the cryptography or the storage. Findings 2, 3 and 5 are where the UX and the threat model pull
against each other, and each is resolved in favour of the threat model.

---

## F. Owner decisions, 2026-11-28

Taken one at a time, each after the trade-off and the threat check were put to the owner.

| # | Decision | Findings touched |
|---|---|---|
| 1 | **The phrase is opt-in.** It is offered, not forced. People who foresee coercion take it at a time they choose. This reverses rollout decision 10 and the forced migration of §3.1 and §3.2. It is consistent with decision 5, "the passphrase stays optional". | 1, 4, 10, 11 |
| 2 | **The offer.** To an install with a PIN, at the first unlock after the update: a short, neutral explanation of the feature and three choices, **Migrate Now** (the setup ladder), **Remind me Later** and **Dismiss**. It stays available in Settings after a Dismiss. See "The offer" below. | 1, 4 |
| 3 | **Every PIN install moves to the new store silently at the update,** under today's device-only key, with the PIN as the lock screen (§1.4's path; the PIN adds no entropy today, so protection is unchanged). Migrate Now only replaces that key with a phrase. This is so that opting in marks no one (Rule 3). | 1, 11 |
| 4 | **Secure Mode installs stay on the old store until they opt in,** with the same offer. Migrate Now runs the existing setup, all phrases in one sitting (Rule 2), at a time they choose. Their mark is today's `app.layer.key.occulta.v1` keychain item, which opting in removes. No silent move of layers is designed. | 1, 11 |
| 4b | **No release-wide date and no gate.** The old store is deleted at the first cold-launch unlock after setup that opens a space with content. | 1 |
| 5 | **Unlock tap:** the lock screen stops at 7 words, and nothing is derived until an explicit Unlock. | 2, 5 |
| 6 | **Label: "Lock now"**, in Settings > Security. Not "Switch Account" or "Switch space". | 6 |
| 7 | **No in-memory switching toggle.** Switching is typing the other phrase. | 6, §D |
| 8 | **An icon-only padlock** in the top bar of every tab, as a second route to Lock now. | 6 |
| 9 | **Grace is fixed at 5 minutes,** with no setting. | 4 |
| 10 | **Setup copy** asking the person to put a contact or note in each space, the same for every phrase. An empty decoy stays unverifiable by its owner; that residual is taken. | 3 |
| 11 | **No word swaps at setup.** Phrases are exactly as drawn. | 14 |
| 12 | **A write into a stray space is accepted.** No first-write notice; finding 2's suggestions 2 and 3 are adopted (uniform empty state, dismissible hint after a typed phrase, no prompt on the first write). | 2 |

**The offer.** Constraints that follow from the threat model, to be built in:
- **Neutral copy.** It appears at whichever PIN was typed, including a duress layer, so it can't mention coercion,
  duress, spaces or hidden data. "Replace your PIN with a stronger 7-word passphrase" is the level of claim.
- **Identical at every PIN layer.** Showing it only at the real layer would mark the others. Migrate Now at a duress
  layer starts setup there, as rollout 8a already allows.
- **One install-wide state, never per layer:** not yet offered, remind after a date, dismissed. Every PIN install
  writes it the same way. A stored date is a per-install trace, no more revealing than the update's own date.
- **Not shown on installs with no lock;** they set a phrase when they turn the lock on (§1.4).
- Nothing here uses notifications or badges (`OSTraceTests`).

**Also decided 2026-11-28**
- **"Remind me Later" waits 7 days.** One stored date, written at the tap. The offer returns at the first unlock after
  it, and tapping Later again re-arms it. Dismiss ends it, and Settings keeps the feature.
- **8a stands for Secure Mode installs, with a "drop that layer" choice** (finding 11). A layer can migrate alone from
  any layer, the old store waits for the real user, and a forgotten decoy phrase can be dropped, the same at every depth.
  The lock screen's layout while the paths coexist is left to stage 6.
- **A plan for the silent move's tests and migration is in §G.**

**Gaps found while writing §G, decided 2026-11-28**
- **Turning Secure Mode on after the silent move: not possible as PIN layers.** `secureMode` is on in the shipped
  `features.plist`, so a PIN-only person can turn on duress PINs today. On an install that has moved, the Secure Mode
  control in Settings > Security becomes the phrase offer (Migrate Now), and extra spaces come from "add a space"
  (finding 7) after they opt in. Existing Secure Mode installs are not moved and keep their controls. This changes a
  feature that ships today, so the release notes have to say so.
- **Downgrade: accepted,** as on 2026-10-16 (`decisions.md`, "Accept the prekey loss on downgrade"). Only TestFlight and
  sideloaded builds can downgrade. The new store is a separate file, so upgrading again finds the data. The case where
  the older build wrote its own store in the meantime stays with rollout decision 18. Add a line to the TestFlight notes.

**What is still open, needs a decision**
- **Nothing is left open in this document.** The follow-ups below, outside it, are what remain.

**Follow-ups outside this document.** The rollout (`PASSPHRASE_ROLLOUT.md`, §3.1, §3.2, §1.2, §8 items 4 and 10, and
the stage 6 rows), the layer-keys spec and `decisions.md` still describe the forced migration. They need rewriting
to match, and the rollout's last open items are on another branch (PR #221), so I have not edited them here. Findings
10, 11 and 12 should be re-read under opt-in.


---

## G. Tests and migration plan for the silent move (§F, item 3)

Applies to installs with a PIN and no Secure Mode layers, and to installs with no lock. Secure Mode installs are never
moved silently. Unit tests for every item; where a real Enclave is needed the suite gates on it, otherwise it injects a
key manager.

**Migration, in order**
1. Seal every row under the install's existing device-only key into a new store, shuffled with the noise rows (rollout
   §8, 23).
2. Open the new store and compare every record with the old one before anything is deleted.
3. Switch the app to the new store, keep the PIN as the lock screen.
4. Only then delete the old store and the keys it alone used. A fault in steps 1 to 3 leaves the old store whole.

**Tests**
- **No data loss.** A seeded old store (contacts with photos, files, notes, the PIN set) moves; every record is equal
  field by field, and the PIN still opens the app.
- **Faulty sealer.** An injected failure at each of steps 1 to 3 leaves the old store untouched and the PIN working.
  No half-built new store remains, and the next launch retries.
- **Interruption.** Killing the process at each step leaves either all-old or all-new, and the next launch finishes.
- **No lock.** An install with no lock moves the same way (§1.4) and opens with no screen, as today.
- **Secure Mode is left alone.** On an install with layers, the silent move does not run and the old store is
  byte-for-byte unchanged (the `InteropVectors.json` approach).
- **Uniform result.** After the move, a PIN-only install and a no-lock install hold the same set of files and keychain
  items, with no per-install value that differs by lock state beyond what Rule 3 allows (an `OSTraceTests`-style test).
- **Migrate Now after the move.** Setting a phrase reseals depth 0 under the phrase, preserves every record, removes the
  device-only key and the PIN gate, and a fault leaves the device-only version whole.
- **The offer.** It is shown at every PIN layer with identical copy, and a string test shows the copy has none of the
  coercion, duress or space words. Dismiss and Later write one install-wide value (never one per layer), Later's date is
  7 days ahead, and it is not shown with no lock.
- **Wrong-phrase flow.** After Migrate Now, a mistyped phrase opens an empty space with no error and takes the same
  time as a right one (finding 2).

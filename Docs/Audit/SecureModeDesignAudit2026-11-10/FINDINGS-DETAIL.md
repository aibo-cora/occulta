# Secure Mode design audit — findings in detail

Commit `87d9bf11` (`v2.0.1/version-bump`). Line numbers refer to that commit. Bug numbers are the ones this
audit files in `Docs/Features/Secure Mode/bugs.md` (220 onwards; see REPORT.md for why).

"Confirmed by test" means a test in `OccultaTests/SecureMode/DuressDeactivationEscalationTests.swift` was run on
the iOS Simulator and fails while the bug is present. "Source only" means the code was read and the claim was
checked by a second reader, but nothing was run; those are leads until a test or a device check settles them.

Severity uses the scale in the audit skill's threat model. It is proposed, not decided.

---

## Bug 220 — A duress PIN alone reaches the real depth through "Deactivate Protection"

**Severity (proposed): critical.** A coercer who holds only a duress PIN ends up at depth 0 and sees every
contact, group and (after Face ID or the device passcode) vault entry the owner hid.

**Status:** open. Confirmed by test, two variants.

### What happens

`deactivateSecureMode` removes the layer the operator is standing in and moves the session one depth
shallower, checking only the PIN of the depth they are leaving:

- `Occulta/Features/SecureMode/Manager+Security.swift:463-466` checks the confirming PIN against
  `sealedNormalVerifiers[depth]`, the current depth's own PIN.
- `:478` `let clearFrom = max(1, depth)` and `:479` clear that depth's verifiers.
- `:488` `let newDepth = max(0, depth - 1)`, `:492` `try self.setState(newDepth, config: config)`.

From depth 1 that lands at depth 0. `setState` changes `sessionID`, so `RootView` rebuilds the unlocked view tree
at the new depth (`OccultaApp.swift:536`), which is the real one.

The button is reachable at a duress depth. `Settings.swift:202-207` shows "Deactivate Protection" when
`state == .normal && (currentDepth == 0 || currentDepth == coercerBaseDepth)`. `coercerBaseDepth` becomes the
current depth as soon as anyone adds a layer from it (`Manager+Security.swift:429-431`), and "Learn more" (add a
layer) is offered at every duress depth by design (`Settings.swift:232`, `plan.md` stack invariant 1).

**Path A, two steps.** The owner has one duress layer. The coercer is given the duress PIN.
1. Lock screen: duress PIN → depth 1, `state == .duress`, "Learn more" shown.
2. Settings → Security → Learn more → "Current Passcode": the duress PIN; "New Passcode": any six digits →
   Activate. `activateSecureMode` writes `coercerBaseDepth = 1`; `state` is now `.normal`.
3. "Deactivate Protection" now shows. Tap it, enter the duress PIN. The session is at depth 0.

**Path B, one step.** The owner at some point added a second layer from depth 1. `coercerBaseDepth` has been 1
ever since, and it is one persisted value shared by every operator. A coercer who enters the first duress PIN
sees "Deactivate Protection" at once.

The master PIN is never entered on either path. Afterwards Secure Mode is off (`sealedDuressVerifier = nil`,
`:490`) and the owner's duress PINs no longer work.

The same step moves an operator from any depth N to N−1 with depth N's PIN. Going further needs depth N−1's
PIN, so one surrendered PIN buys one depth. For the first duress PIN that depth is the real one.

### Why earlier reviews did not catch it

- Bug 45 hid the button at every depth above 0 for exactly this reason: "deactivate only from depth 0, using
  the master PIN" (`bugs.md:1101`).
- Bug 47 brought it back at `coercerBaseDepth` so a coercer who created a layer would not see a missing
  button, and Bugs 58/61 made any activation from depth N set `coercerBaseDepth = N`.
- `scenarios.md` §14.4 step 6 says the coercer's deactivation "strips depth N+2. Returns to depth N+1 state":
  the layer **below** them goes and they stay where they are. The code removes the layer they are **in** and
  moves them **up**. Bug 111 then made the move explicit ("3→2→1→0") and added a test for it.
- `OccultaTests/SecureMode/PINManagerTests.swift:512-514` asserts the landing as intended:
  `try s.deactivateSecureMode(confirmingEntryPIN: "999999")  // depth 1 → pinOnly` then
  `#expect(s.currentDepth == 0)`. Every one of these was written from the real user's point of view.
- `scenarios.md` §6.4 still says "Only depth 0 can deactivate", which the code has not done since Bug 47.

### Proof

`DuressDeactivationEscalationTests.duressPINHolder_activateThenDeactivate_staysAtDepth1` (path A, also checks
that a contact hidden from duress depths becomes visible) and
`duressPINHolder_ownerHasTwoLayers_deactivateStaysAtDepth1` (path B, across a relaunch). Both fail on the
Simulator with `s.currentDepth → 0`. The tests call only what the Settings screen calls, behind the conditions
`Settings.swift` uses to show each button.

Not checked: the on-screen path on a device. The view conditions were read, not driven.

### Fix (proposed)

Adopt now the rule the owner already decided for the passphrase release (`Docs/v2.0.0/PASSPHRASE_ROLLOUT.md:432-436`,
decision 9a): **a depth can remove the depths below it; no depth removes itself or anything above it.**

1. `deactivateSecureMode` at depth D clears `sealedNormalVerifiers[D+1...]` and `sealedDuressVerifiers[D...]`,
   orphans vault entries and backup keys stamped D+1 or deeper, and **leaves `currentDepth` at D**. At D = 0
   that is today's behaviour. `sealedDuressVerifier` (the scalar) clears only when D = 0.
2. `currentDepth` decreases in exactly one place: `applyVerifyState` after `verify` matched that depth's PIN
   (and `reEnablePIN`'s scan, which also matches a PIN). Add a test that lists every writer of `currentDepth`
   and fails if a new one appears.
3. After a removal at D > 0 set `coercerBaseDepth` so the screen returns to "Learn more" at D (there is no
   layer below any more), which is what `scenarios.md` §14.4 describes.
4. Replace the tests that assert the upward pop (`deactivation_fromDepth2_popsOneLevelToDepth1`,
   `deactivation_fromDepth3_popsOneLevelToDepth2`, `deactivation_threeLayerStack_popsOneLevelPerCall`) with
   tests for the new rule, and keep the two tests above as the guard.

The owner loses nothing: from depth 0 they still remove everything with the master PIN. What goes is tearing
a stack down from the bottom up, which only someone at the bottom needed.

Migration: none. No stored format changes.

---

## Bug 221 — Setting a PIN on a lowered lock moves the session one depth deeper, and the decoy's vault empties

**Severity (proposed): high.** The holder of the phone can tell that depths exist: content they were shown
disappears as a result of turning a PIN on.

**Status:** open. Confirmed by test.

### What happens

The owner lowers the lock at depth N (`disablePIN`, `Manager+Security.swift:868`) and hands the phone over. The
app opens at depth N with no PIN, and Settings shows "Enable PIN" off, as on an install with no PIN.

The holder turns "Enable PIN" on and enters a PIN of their own twice (`Settings.swift:263-270`). The PIN
matches nothing, so `reEnablePIN` takes the coercion-acceptance branch (`Manager+Security.swift:969-989`): it
writes the PIN as `sealedDuressVerifiers[N]` and as the routing alias `sealedNormalVerifiers[N+1]`. The session
stays at depth N until the next lock. At the next lock screen their PIN routes to **depth N+1**
(`verify`, `:674-679`).

Depth N+1 is not depth N:
- Vault entries match their depth exactly (`visibleVaultEntries`, `:1053-1059`), so every entry made at depth N
  is gone. So is depth N's backup key and trustee setup (`BackupEncryptionKey.depth`).
- Going deeper purges drafts (`applyVerifyState`, `:759-761`; `purgeDraftsNotSafeAtCurrentDepth`, `:797-808`):
  every group draft, and drafts to contacts not visible at N+1.
- Contacts whose `visibleThroughDepth` is exactly N disappear.

On an install that really had no PIN, setting one changes nothing on screen. Here the vault the holder just
looked at is empty after they set a PIN. `scenarios.md` §4.8 records the routing ("Next PIN entry with C routes
to depth N+1") but not what it does to the content.

There is a second effect. If the owner already had a layer N+1, its PIN is overwritten without warning
(`:976-977`) and the holder inherits that layer's content.

### Proof

`DuressDeactivationEscalationTests.loweredLock_settingAPIN_keepsTheSameDepthAndVault` fails with
`s.currentDepth → 2` and `visibleVaultEntries(...).count → 0`.

### Fix (proposed)

Make the holder's PIN the PIN **of depth N**, not of a new depth: in the coercion-acceptance branch write the
new verifier into `sealedNormalVerifiers[N]` and `sealedDuressVerifiers[N-1]` (replacing the owner's duress
PIN for that depth) and leave deeper slots alone. The holder's PIN then opens exactly what they were looking
at. The owner still reaches depth 0 with the master PIN and can set a new duress PIN from there.

Cost to decide: the owner's old duress PIN for depth N stops working. If that is not acceptable, the
alternative is to make depth N+1 a copy of depth N's view (ceiling instead of exact match for that pair), which
is a larger change and reopens the leak the exact match closed (`Docs/Bugs/v1.10.0/Vault-Entries-Created-At-A-Duress-Depth-Leak-Into-The-Real-Vault.md`).
**Open, needs a decision.**

---

## Bug 222 — The app-switcher cover appears only when Secure Mode is active

**Severity (proposed): high.** One gesture shows that a duress layer exists, at any depth, with or without a PIN.

**Status:** unconfirmed (source only; needs one look on the Simulator or a test phone).

### What happens

`AppScreen` covers the window with a blank view and a spinner when the scene resigns active, so the
app-switcher card and the saved snapshot show nothing. It does so only if a duress verifier exists:

- `Occulta/App/AppScreen.swift:73-77` and `:82-86`: `guard self.secureModeActive else { return }` before
  `installCover`.
- `:89-92`: `secureModeActive` is `security.isSecureModeActive`, which is `sealedDuressVerifier != nil`
  (`Manager+Security.swift:84-87`).

So on an install with no PIN, or a PIN and no Secure Mode, the app-switcher card shows the contacts list. On an
install with Secure Mode it shows a blank card with a spinner, at every depth, including a duress depth that
is meant to look like an ordinary install, and including a lowered lock where the app claims to have no PIN.

A coercer who knows the app (the behaviour is in the public source and documented in
`forensic-trace-avoidance.md` U5d: "No-op for users without Secure Mode configured") swipes up and looks. The
same difference is on disk: the snapshot under `Library/SplashBoard/Snapshots/` is a spinner on one kind of
install and app content on the other.

The documents treat the condition as a courtesy to users without Secure Mode (no spurious flash). None treats
it as an observable.

Separately, installs without Secure Mode get no snapshot protection at all: their contacts list is written
into the snapshot file on every backgrounding.

### Local validation plan

Simulator, two fresh installs: (a) set a PIN only; (b) set a PIN and activate Secure Mode, unlock with the
duress PIN. Background each and compare the app-switcher card. Then a unit test once the condition is a
function: `AppScreen.shouldCoverOnResign` returns true for every `Manager.Security` state.

### Fix (proposed)

Install the cover on every resign, on every install, whatever the PIN or Secure Mode state. Remove
`secureModeActive`. The flash on share sheets and Face ID prompts that the condition avoided then applies to
everyone; if that is unwanted, cover on `sceneDidEnterBackground` minus the cases U5d lists, but the same way
for everyone.

---

## Bug 223 — With the lock lowered, "Learn more" stays enabled and asks for a current passcode

**Severity (proposed): medium.** Needs the lowered-lock state. In that state it shows a PIN still exists.

**Status:** unconfirmed (source only).

### What happens

`Settings.swift:232-243`: the "Learn more" section is dimmed and disabled when `!self.requiresPIN`, where
`requiresPIN` is `sealedNormalVerifier != nil` (`:197`). The toggle shows off when
`requiresPIN && security.pinEnabled` is false (`:216`).

| Install | "Enable PIN" toggle | "Learn more" |
|---|---|---|
| Never had a PIN, or PIN turned off | off | dimmed, disabled |
| Lock lowered at a duress depth | off | **enabled** |

Tapping it opens `SecureModeSetupFlow`, whose second step is `PINEntry(.confirmThenSet)`, titled **"Current
Passcode"** (`PINEntry.swift:90`), on a phone whose Settings say there is no PIN.

`scenarios.md` §14.5 compares the lowered lock with "`.pinOnly` gate-down". There is no such state: turning the
PIN off without Secure Mode removes it (`deactivatePIN`), which is the dimmed row.

### Fix (proposed)

Key the section's enabled state on what the toggle shows: `self.requiresPIN && self.security.pinEnabled`.
With the lock lowered the row is then dimmed like a no-PIN install, and the setup flow is not reachable until
a PIN is "set" (Bug 221's path).

Guard: move the three visibility conditions of `SecuritySettings` into one pure function of
(`requiresPIN`, `isSecureModeActive`, `state`, `pinEnabled`, `currentDepth`, `coercerBaseDepth`) and test that a
lowered lock at depth N > 0 yields the same result as no PIN.

---

## Bug 224 — A correct PIN of any depth resets the lockout, so a duress PIN holder can guess the master PIN without limit

**Severity (proposed): medium.** A new variant of Bug 62's open "no attempt limit" gap, at the lock screen
instead of the setup flow.

**Status:** open. Confirmed by test:
`DuressDeactivationEscalationTests.duressPINHolder_isLockedOutWhenGuessingAnotherPIN` makes 200 wrong guesses
in rounds of five with the duress PIN between rounds and is never locked out.

### What happens

`verify` counts consecutive wrong PINs and locks from the sixth (`Manager+Security.swift:693-699`, `:704-723`).
A correct PIN at any depth clears the count (`:677`, `:687`). A coercer who holds a duress PIN enters five
guesses, then their own PIN, and repeats. The count never reaches six. Each guess is tested against all 32
normal verifiers (`:674-680`), so a hit on the master PIN opens depth 0.

Six digits is 10⁶ PINs, about 1.2 million entries including the resets. By hand that is weeks; with a
keypad robot, days. The 500 ms response pad (`PINEntry.swift:74`) is the only brake.

### Fix (proposed)

Rate-limit wrong attempts on a window that a correct PIN does not clear: keep the count and its uptime anchor,
and let them decay with elapsed uptime (for example one attempt forgiven per hour) instead of resetting on
success. It applies to every install the same way, so it is not a tell. Do not make the reset depend on which
depth's PIN was entered: that would itself be observable.

---

## Bug 225 — `AppLayerConfig.sealedDuressVerifier` is NULL until Secure Mode is activated

**Severity (proposed): low** today (with the passcode an examiner reads everything anyway, Bug 119);
it becomes the cheapest tell once the passphrase work removes the others.

**Status:** unconfirmed (source only).

### What happens

`AppLayerConfig+Model.swift:22-23`: `sealedNormalVerifier` and `sealedDuressVerifier` are optional columns used
as flags: "PIN set" (`Manager+Security.swift:79-80`) and "Secure Mode active" (`:85-86`, `Settings.swift:198`).
The second is nil on every install that has not activated Secure Mode (`:490`, `:525` clear it; `:413` sets
it). Anyone who can read the SQLite file sees NULL or 81 bytes in `ZSEALEDDURESSVERIFIER` without any key.

Everything else in the row was built to avoid this: the arrays are padded to 32 with random filler, and
`persistedDepth`, `coercerBaseDepth` and `pinEnabledPerDepth` are seeded at first launch "so their presence
never leaks state" (`plan.md`). `forensic-trace-avoidance.md` K1 says the row is "all opaque Data"; that does
not hold for the two scalars. `PASSPHRASE_ROLLOUT.md:219` and `:374` concede the normal scalar (a lock exists)
and are open; the duress scalar is not discussed anywhere.

The lockout fields have the same shape with less to tell: `lockoutCountEncrypted` and
`lockoutAnchorUptimeEncrypted` are NULL except between a wrong PIN and the next correct one (`:361-364` of the
model), and their sealed length varies with the JSON text of the number.

### Fix (proposed)

Seed both scalars with random filler of verifier size at first launch and stop using nil as the flag: read
"PIN set" and "Secure Mode active" from a sealed, fixed-width state value (one byte, sealed, always present),
or from whether slot 0 of each array opens under the PIN in hand. Seed the lockout fields with a sealed zero
and write fixed-width values.

Migration: on first launch after the change, fill a nil scalar with filler and write the state value from the
old nil/non-nil reading, in the same save. Cover with a test that an install with no PIN, one with a PIN and
one with Secure Mode have the same NULL pattern and the same column lengths in `AppLayerConfig`.

---

## Bug 226 — PIN checks made from Settings are not counted, and `reEnablePIN` tests a guess against every depth's PIN

**Severity (proposed): medium.** An unthrottled search for another depth's PIN from inside the unlocked app.

**Status:** open. Confirmed by test. Found by a hunter, checked by a separate verifier.

### What happens

`checkCurrentLayerPIN` (`Manager+Security.swift:1003-1025`) and `reEnablePIN` (`:909-990`) never read or write the
lockout counter and do not honour a lockout in force. `plan.md` built them that way on purpose: a Settings
confirmation "is not a lock-screen attack attempt". At a duress depth the unlocked session is the coercer's.

**Path 1, a holder of the depth-N PIN.** Lower the lock (`disablePIN`, confirmed with their own PIN), then turn
"Enable PIN" on with a guess. `reEnablePIN` tests the guess against all 32 normal verifiers and then all 32
duress verifiers (`:918-936`). A hit calls `setState(k)`: the master PIN moves the session to depth 0 on the
spot, with no lock screen. A miss creates a layer and reports success, so nothing on screen says the guess was
wrong; they lower the lock again and repeat. Three PIN entries a guess, no limit.

**Path 2, a holder of the phone with the lock lowered and no PIN.** "Learn more" is enabled (Bug 223). Its
first step checks depth N's PIN with `checkCurrentLayerPIN` (`PINEntry.swift:284-302`): half a second a guess,
no counter. With depth N's PIN, Bug 220 leads to depth N−1. The verifier judged this half weaker: it is a
six-digit search by hand.

Bug 62's Gap 2 (no limit on collision probes in the activation flow) is a third path of the same kind and is
already open.

### Proof

`DuressDeactivationEscalationTests.settingsPINChecks_areCountedLikeTheLockScreen`: 100 wrong guesses through
`disablePIN`/`reEnablePIN` and 1,000 through `checkCurrentLayerPIN` leave `lockoutExpiry()` nil, and
`reEnablePIN("111111")` then sets `currentDepth` to 0.

### Fix (proposed)

One attempt counter for every PIN check (with Bug 224's rule that a correct PIN does not clear it), refused
while a lockout is in force. `reEnablePIN` matches only the current depth's PIN or a deeper one; reaching a
shallower depth always goes through the lock screen. The owner who lowered the lock at depth N and wants depth
0 back locks the app and enters the master PIN, which needs the lowered lock to offer a way to lock (today it
has none: with `pinEnabled == false` there is no lock screen). **Open, needs a decision** together with what
the lowered lock is for (DESIGN-REVIEW.md, recommendation 6).

---

## Bug 227 — The grace period is measured on the wall clock, so setting the clock back skips the PIN

**Severity (proposed): critical, conditional.** Whoever can change the device clock while Occulta is still in
memory returns to the depth it was left at, usually depth 0, with no PIN. The condition is an unlocked device
(or its passcode) and a suspended process, which modern iPhones keep for hours.

**Status:** open for the app's logic, confirmed by test. Not observed end to end: that the suspended process
survives a change in Settings → Date & Time was assumed. Found by a hunter, checked by a separate verifier, who
found no other place the phase becomes `.pinRequired` on a warm return and no clock-change observer.

### What happens

- `Occulta/App/AppScreen.swift:96`: `self.backgroundEntryDate = Date()` on entering the background.
- `:158-165` `lockIfGracePeriodExpired`: locks only if `now.timeIntervalSince(entered) > gracePeriod`.
- `:183` `evaluate`: `Date().timeIntervalSince($0)`, and within the grace period sets `.unlocked`.

A clock set back makes the time away short or negative. Neither check fires and the app returns unlocked.
`Manager.Security.currentDepth` is in memory and is not reset when the app locks, so the session resumes at the
owner's last depth.

The PIN lockout was moved off the wall clock for this reason ("SEC-1", `Manager+Security.swift:649-669`). The
grace period was not. The clock the lockout uses, `ProcessInfo.systemUptime`, does not count time asleep, so it
would be the wrong one here, and it makes a lockout last longer than it says.

### Proof

`DuressDeactivationEscalationTests.clockSetBackWhileAway_stillAsksForThePIN`:
`lockIfGracePeriodExpired(now: entered − 1 h)` leaves `phase == .unlocked`.

### Fix (proposed)

Measure the time away on a clock the user cannot set and that counts sleep (`ContinuousClock`), and treat a
negative or unreadable interval as expired. A reboot ends the process; a cold launch already asks for the PIN.
Add `UIApplication.significantTimeChangeNotification` as a second line: on a significant time change while in
the background, lock.

---

## Bugs 228–235

Written up in full in `Docs/Features/Secure Mode/bugs.md`; summarised in REPORT.md §1. In short:

- **228** (high): SwiftData's history log. Known as a store-wide item under Bug 196/190; new here are the
  Secure Mode writes it records, which depend on the depth. Test: `StoreForensicTraceTests.secureModeWrites_leaveNoHistoryRows`.
- **229** (medium): `secure_delete = ON` set on a helper connection is not in force on the next one (FAST is).
  Test: `StoreForensicTraceTests.secureDelete_setOnOneConnection_isOnForTheNext`.
- **230** (medium): rename and delete of a real-depth group from a duress depth. Source only.
- **231–235** (low): classification overwriting a deeper limit; the Private toggle on a duress-origin
  contact; a new layer overwriting a deeper one; the backup-export record of a freed depth; Erase All Data's
  leftover rows. Source only.

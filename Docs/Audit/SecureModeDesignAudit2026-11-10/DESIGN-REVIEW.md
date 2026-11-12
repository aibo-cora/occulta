# Secure Mode — design review

Part of the Secure Mode design audit of 2026-11-10 (commit `87d9bf11`). This file looks at the design as
written and as built. The findings it refers to are in [FINDINGS-DETAIL.md](FINDINGS-DETAIL.md).

## What "Secure Mode" is on this commit

A six-digit PIN lock and a stack of depths. Depth 0 is the real app; depth N > 0 is a decoy the owner
surrenders. A PIN routes to a depth. Every depth's rows sit in one SwiftData store under one device-released
key, and the app filters what it shows by the depth in memory (`Manager.Security.currentDepth`).

Not on this commit: the sensitive-contact blob and the key rotation at activation (removed 2026-09-10), and
the diceware phrases with per-depth keys (`PASSPHRASE_LAYER_KEYS.md`, `Docs/v2.0.0/PASSPHRASE_ROLLOUT.md`,
proposed for a later release).

## Does the design hold against its threat model?

**Against an examiner with the passcode: no, and the documents say so.** `Docs/v2.0.0/README.md` states that the
app adds nothing beyond the device passcode today (Bug 119). That is an accurate statement of the design, and
this audit adds nothing to it. The user guide does not say it; see "Documents" below.

**Against a coercer inside the unlocked app at a duress depth: the design's own invariants are broken in four
places**, each by a rule that was added to make the decoy look more like a real install:

1. *A depth transition towards the real data must need that depth's PIN.* The design never states this
   rule. `deactivateSecureMode` moves the session one depth shallower with the PIN of the depth being left
   (Bug 220), and `AppScreen` skips the PIN altogether when the clock reads as inside the grace period
   (Bug 227). The lockout that should slow a search for the master PIN is reset by any correct PIN and does not
   apply inside Settings (Bugs 224, 226).
2. *The decoy must behave like an install that never used Secure Mode.* The rule is applied screen by
   screen, and the comparison install is sometimes one that cannot exist. The lowered lock is compared with
   "`.pinOnly` gate-down" (`scenarios.md` §14.5); there is no such state. The result is a "PIN off" screen
   whose "Learn more" row is live and asks for a current passcode (Bug 223), and a "set a PIN" action that
   empties the vault (Bug 221). The app-switcher cover is installed only for Secure Mode installs (Bug 222).
3. *The coercer cannot determine how many layers exist.* `coercerBaseDepth` is one persisted value shared by
   every operator. It records where the last layer was added or removed, and the Settings screen at that
   depth changes for whoever arrives next ("Deactivate Protection" in place of "Learn more").
4. *Fields are always present and constant-length.* True for the arrays, not for the two scalar flags or the
   lockout fields (Bug 225).
5. *The store shows the same thing whichever depth was used.* The forensic rules cover the model's sealed
   columns. They do not cover what the storage framework writes beside them: SwiftData's history log records,
   with times, the draft purge that only a deeper unlock performs, and every change to the Secure Mode
   configuration (Bug 228). The `secure_delete` setting the purges rely on is not the one in force on a new
   connection (Bug 229).

The pattern behind items 1–3 is the same. Each fix in the bug history (45, 47, 48, 58, 61, 111) was reasoned
from one operator's point of view, usually the real user's. The state it added is shared by all operators.
Nothing in the design forces the question "who else reaches this state, and holding what?".

## Gaps between the written design and the code

| Document | Says | Code |
|---|---|---|
| `scenarios.md` §6.4 | "Only depth 0 can deactivate" | Any depth equal to `coercerBaseDepth` can (`Settings.swift:202-207`) |
| `scenarios.md` §14.4 step 6 | Coercer's deactivation "strips depth N+2. Returns to depth N+1 state" | Removes the layer they are in and lands one depth shallower (`Manager+Security.swift:478-492`) |
| `scenarios.md` §6.1, §1.6, §11–§13, §15 | Key rotation, blob restore, layer store | Removed 2026-09-10 |
| `scenarios.md` §14.5 | Lowered lock is "identical to `.pinOnly` gate-down" | No such state exists |
| `plan.md` "Wipe threshold behaviour" | "SE hardware rate-limiting is the brute-force defence" | There is none; the Enclave does not rate-limit ECDH. The app-level lockout is the only limit, and it resets (Bug 224) |
| `plan.md` public interface | `isSafeContact`, `safeContactIDs`, `updateSafeContacts` on `Manager.Security` | Live on `ContactManager` |
| `forensic-trace-avoidance.md` K1 | `AppLayerConfig` is "all opaque Data" | Two optional scalars are plain presence flags |
| `forensic-trace-avoidance.md` U5d | The cover is a no-op without Secure Mode, as a courtesy | That condition is itself the observable (Bug 222) |
| `SecureMode+RotationContract.md`, `LayerStore.md` | Rotation and blob contracts | Describe removed code. (`SecureMode+LayerStoreBackend.swift` is still live: the vault's legacy backup migration uses it) |
| `PINManagerTests.swift:512-514` | Asserts depth 1 → depth 0 with the duress PIN as intended | This is Bug 220 |

Dead code noted in passing, not removed: `forceDeactivateForRecovery` and `checkNormalPIN` have no production
caller. If either is wired to a screen later, it checks the master PIN from any depth with no attempt counter.

## Documents the user reads

`Docs/Features/Secure Mode/USER_GUIDE.md` contradicts itself and the code. It says "The hiding is done by the
app itself, not by separate encryption keys", and a page later "Your real contacts remain encrypted on the
phone. Even law enforcement cannot decrypt them without your master PIN" and "Even Apple cannot decrypt your
data without your PIN". The PIN is not a key, and every depth opens with the device passcode. The register
already lists this under §E. It matters more than a wording issue: a user deciding what to put in the app reads
it as a guarantee.

It also says of the coercer: "No button to disable it (it's hidden)". Bug 220 is that button.

## Recommendations

**Before any release that keeps the PIN design**

1. Write the depth-transition rule into the design and enforce it in one place: `currentDepth` decreases only
   after the PIN of the target depth was matched. Adopt decision 9a now ("no depth removes itself or anything
   above it"). Add a test that enumerates every writer of `currentDepth`.
2. Replace the operator-specific state (`coercerBaseDepth`) with a rule that is a function of the current
   depth and what lies below it only. With rule 9a the screen at depth D needs just one fact: whether a layer
   below D exists. That is the same at every depth and says nothing about who put it there.
3. Make every observable of "Secure Mode is active" unconditional: the cover, the scalar flags, the lockout
   fields. A useful test is a table of installs (no PIN; PIN; Secure Mode at depth 0; duress depth; lowered
   lock) against observables (Settings rows, app-switcher card, column NULL pattern), asserted equal where the
   design says they must be.
4. Measure the grace period and the lockout on a clock the user cannot set and that counts sleep, and treat a
   negative interval as expired.
5. One attempt counter for every PIN check that can reveal or reach another depth: the lock screen,
   `reEnablePIN`, `checkCurrentLayerPIN`, and the collision check in `activateSecureMode` (Bug 62 Gap 2). A
   correct PIN must not clear it.
6. Decide what the lowered lock is. As built it tries to pass for "no PIN" and cannot: verifiers exist, the
   setup flow asks for them, and setting a PIN moves depth. Either make it a true alias of the depth (Bug 221's
   proposed fix plus Bug 223's) or drop the feature; the passphrase plan already replaces it with the
   coercion gate (decisions 7a–7d).

6a. Treat the storage framework as part of the forensic surface. Add its tables and settings to
   `forensic-trace-avoidance.md` (history log, `Z_PRIMARYKEY`, `secure_delete`, checkpoint results) and test
   them against an on-disk store, not only the model. The 2.1.0 plain SQLite store removes the log; decide what
   2.0.1 does until then.
6b. Scope destructive actions on shared rows. A group is one row for every depth; rename and delete from a
   duress depth act on the real depth's data (Bug 230). The same question applies to Erase All Data, already
   open.

**Process**

7. For every Secure Mode change, write down three operators before the code: the owner at depth 0, a holder
   of exactly one duress PIN, a holder of the phone with the lock lowered and no PIN. State what each sees
   and can do. `scenarios.md` is the place, once the removed-machinery sections are cut.
8. Retire or rewrite `scenarios.md`, `plan.md` Steps 3+, `LayerStore.md`, `SecureMode+RotationContract.md` and
   the user guide's encryption claims. A reviewer who trusts §6.4 will not look for Bug 220.

**For the passphrase design**

9. Carry items 1–5 into it explicitly. Per-depth keys remove the "one key opens everything" problem but not
   these: a session that changes depth in place, a shared attempt counter, and unconditional observables are
   properties of the state machine, not of the key hierarchy.
10. `PASSPHRASE_ROLLOUT.md` decision 9a says the removal option "behaves the same at every depth". Check that
    against a depth with nothing below it: an option that does nothing at the bottom and something elsewhere
    tells the operator whether they have reached the bottom.

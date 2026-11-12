# Secure Mode design audit — what each lead still needs

Every record in `findings.json` is `needs_validation`: the audit's agents read source and ran nothing. The
auditor then ran Simulator tests for seven leads. This file says what is settled and what is not.

Simulator only. Connected iPhones hold real data; a device check waits for a phone with none.

| Bug | Settled by a test | Still needed |
|---|---|---|
| 220 | Yes: the calls the Settings screen makes land at depth 0 with only the duress PIN | Drive the on-screen path once (Simulator: Settings → Security at depth 1). The view conditions were read, not run |
| 221 | Yes: depth 1 → 2 and the depth-1 vault entry gone | A decision on the fix (it costs the owner's old duress PIN for that depth) |
| 222 | No | Two Simulator installs, one PIN-only and one unlocked with a duress PIN; background both and compare the app-switcher card. Then a unit test once the condition is a function |
| 223 | No | Extract `SecuritySettings`' visibility conditions into a pure function and test lowered lock at depth N against no PIN |
| 224 | Yes: 200 wrong guesses, no lockout | Nothing before the fix |
| 225 | No | Open an on-disk store after first launch and after activation; compare `ZSEALEDDURESSVERIFIER IS NULL`. Assumes SwiftData stores a nil `Data?` as NULL |
| 226 | Yes: 1,100 uncounted wrong PINs, then the master PIN moves the session to depth 0 | A decision on how the owner returns from a lowered lock if `reEnablePIN` stops matching shallower depths |
| 227 | The app's logic: a clock an hour behind the background time leaves the phase unlocked | End to end on a phone with no real data: background Occulta, wait past five minutes, set the clock back, reopen |
| 228 | Yes: history rows with changed-column masks after a PIN, an activation and a wrong PIN | An update row for `Profile.visibleThroughDepth` and a `Draft` delete transaction were not produced in the test; add them. Whether SwiftData can open the store with history off |
| 229 | A new connection reports FAST after the pragma | What SwiftData's own connections run with; whether freed pages hold old ciphertext (delete a row with a marker, checkpoint, search the store, `-wal`, `-shm`) |
| 230 | No | Test in the bug entry's Guard |
| 231 | No | Test in the bug entry's Guard (three depths) |
| 232 | No | A decision first: is a duress-origin contact meant to be un-hideable from deeper depths? |
| 233 | No | Test in the verifier's record: layers to depth 3, activate from depth 1 |
| 234 | No | Test in the verifier's record: export at depth 2, deactivate, re-create, check `backupStaleness` |
| 235 | No | Test: after `eraseAllData` the store equals a fresh install's |

Run one suite at a time:

```
xcodebuild -project Occulta.xcodeproj -scheme OccultaTests \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' \
  -only-testing:OccultaTests/DuressDeactivationEscalationTests test
```

and the same with `StoreForensicTraceTests`. Two "iPhone 17 Pro" simulators exist on the audit machine; the
audit ran against one by id.

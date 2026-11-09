# Occulta Measure

A small standalone iOS app that measures what the passphrase unlock will cost, on the hardware it runs on. It exists
because stage 0 of `Docs/v2.0.0/PASSPHRASE_ROLLOUT.md` needs device timings (§8, items 6, 21, 22, 26, 27), and a
hosted Occulta test run on a real phone deleted its groups (`bugs.md` Bug 192), so nothing is ever hosted in
`Occulta.app` on a phone again.

It is not a target of `Occulta.xcodeproj`, has no package dependency, and links no Occulta code. The logic it needs
is copied from `OccultaTests/SecureMode/ContactRecordCryptoMeasurementTests.swift`.

| | |
|---|---|
| Bundle ID | `com.github.aibo-cora.occulta.measure` (its own App ID; iOS keeps its container and keychain apart from Occulta's) |
| Team | `R6F5KHKKNX`, the app's |
| Deployment target | iOS 18.6, as the app's; the ML-KEM step runs on iOS 26+ |
| Stores | Nothing. Keys are transient (`kSecAttrIsPermanent: false`, no keychain item). Files go in the app's temporary directory and are all removed when the run ends. No entitlements, no App Group, no keychain access group |

## Run it

**On the Simulator.** The scheme builds Release, which is the only configuration whose numbers mean anything (a Debug
build says so at the top of the report):

```bash
xcodebuild -project Tools/OccultaMeasure/OccultaMeasure.xcodeproj -scheme OccultaMeasure \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' build
```

Then run it from Xcode (open `Tools/OccultaMeasure/OccultaMeasure.xcodeproj`, Cmd+R) and tap **Run measurements**,
or install the built `.app` with `xcrun simctl install` and launch it with `--autorun`, which runs at launch and
logs the report line by line with `NSLog`. The run takes a minute or two on a Mac. The report is on screen as
selectable text, with a share button for sending it as text.

Simulator numbers are the Mac's CPU, SQLite and Enclave. They show the report works and nothing more; **they are not
what an iPhone 11 will do.**

**On a device: manual, and only the user's call.** This app was built and run on the Simulator only. Every phone the
user has holds real Occulta data, so installing is decided per phone, by naming the phone. This app can't reach
Occulta's data, but it is installed and launched by hand:

1. Pick the phone (the iPhone 11 for the iteration count, §8 item 6).
2. In Xcode, select the phone as the run destination and Cmd+R, with the scheme's Release configuration (the default).
3. Charge it, turn Low Power Mode off, let it cool, keep it unlocked and awake, and close other apps. The report's
   header records the thermal state and Low Power Mode; discard a run where either was off nominal.
4. Run it two or three times and compare. Delete the app afterwards.

If the project is changed, `project.yml` is its source: `xcodegen generate` in this folder rewrites the `.xcodeproj`.

## What is measured

Every figure is the median of several passes, with min, max and the number of passes beside it.

| Section | What it times | Feeds |
|---|---|---|
| PBKDF2-HMAC-SHA256 | CommonCrypto's `CCKeyDerivationPBKDF` over 7 word indices (two bytes each, a stand-in for the encoding that isn't built) and a 32-byte salt. The iteration count that takes about 1 s (calibrated, rounded to 10,000 and re-measured), `CCCalibratePBKDF`'s own figure for comparison, and 100k, 300k, 600k, 1M and 2M iterations | The iteration count, to be tuned to about 1 s on an iPhone 11 (A13): spec §4, §8 item 6. Raising it later reseals every row, so it is chosen on the slowest phone |
| Space-key derivation | A transient Secure Enclave P-256 key, ECDH against a point derived from the PBKDF2 output, HKDF; on iOS 26 also a transient Enclave ML-KEM-1024 decapsulation. The total, and the point, the ECDH and the decapsulation alone | What a key-cache refill and the grace-period return cost (§8 item 27's 4.6 ms on an iPhone 15 Pro), and unlock's fixed part. The point is derived from the PBKDF2 output here, so its cost shows separately; the design's fixed point costs none |
| Contact table | A plain SQLite file through the `sqlite3` C API: a `WITHOUT ROWID` table keyed by random 16-byte IDs, 100, 1,000 and 5,000 sealed 8,220-byte records plus 1,000 noise rows. Reading every row, trial-decrypting each (AES-GCM; a noise row fails its tag) and decoding the real ones, separately and together, and the first pass | Unlock's cost at scale; the noise-row cap, §8 item 21; the table that only grows, item 22 |
| Photos | 100 rows of 24 KB with no noise; fetching one by ID, with and without decrypting it | Photo display latency, §1.5 |
| Vault | 20 entries of 4 KB and 200 noise rows; reading and trial-decrypting all of them | The vault's unlock cost, §1.5 |
| WAL after closing | Whether `-wal` and `-shm` still exist after the last connection closes, with and without a `wal_checkpoint(TRUNCATE)` first, and Apple's SQLite defaults (`journal_mode`, `secure_delete`, whether the WAL persists) | §8 item 26's second test and decision 26: the store must delete its `-wal` on close, and a persistent WAL default would need turning off |

Every store is opened with `PRAGMA secure_delete=ON` and `PRAGMA journal_mode=WAL`, and the report says so. The
contact table's first pass is the closest it gets to a cold start: the OS page cache can't be dropped from an app.
All keys and rows are mock and random; AES-GCM's cost does not depend on them.

## What it does not do

- It never reads or writes Occulta's container, keychain, App Groups or `Manager.Key`.
- It writes nothing outside its temporary directory, and removes a directory left by an earlier killed run when it
  starts.
- It does not measure writes, shreds or the migration; those wait for the store layer.

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
logs the report line by line with `NSLog`. The run takes several minutes on a Mac (it builds and reads 0.1–0.7 GB tables nine times). The report is on screen as
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
| PBKDF2-HMAC-SHA256 | CommonCrypto's `CCKeyDerivationPBKDF` over 7 word indices (two bytes each, a stand-in for the encoding that isn't built) and a 32-byte salt. **The smallest multiple of 10,000 iterations whose median of 5 passes is at least 1 s**, found by searching from a calibrated estimate (up while a count falls short, then down while the next one below still reaches 1 s) and reported with the count below it; `CCCalibratePBKDF`'s own figure for comparison; and 100k, 300k, 600k, 1M and 2M iterations | The iteration count, set on an iPhone 11 (A13): spec §4, §8 item 6. Raising it later reseals every row, so it is chosen on the slowest phone. A median is good to a few steps of 10,000 |
| Space-key derivation | A transient Secure Enclave P-256 key, ECDH against a point derived from the PBKDF2 output, HKDF; on iOS 26 also a transient Enclave ML-KEM-1024 decapsulation. The total, and the point, the ECDH and the decapsulation alone | What a key-cache refill and the grace-period return cost (§8 item 27's 4.6 ms on an iPhone 15 Pro). The point is derived from the PBKDF2 output here, so its cost shows separately; the design's fixed point costs none, and the contact table's figure below leaves it out |
| Contact table | The one small-records table of §1.5 (decided 2026-11-15) and its row size (§8 item 29), at **32, 48 and 64 KB** rows (`Measurement.rowSizes`; the size is set later, bottom-up, and estimated at 48–64 KB) and **100, 1,000 and 5,000 contacts**. Per contact, one contact row and one 24 KB photo row, both padded to the row size, with the type as the first byte inside the seal; plus 1,000 noise rows. A plain SQLite file through the `sqlite3` C API, a `WITHOUT ROWID` table keyed by random 16-byte IDs | Unlock's cost at scale (§1.5, §8 items 21, 22, 29) |
| What one unlock pass does | Streams the table row by row, as unlock would: read the row, trial-decrypt it (AES-GCM; a noise row fails its tag), read its type, decode a contact, **drop a photo's plaintext** without decoding it. It adds the Enclave derivation with the fixed point. Each phase is timed separately and the four are summed | "Everything after PBKDF2" |
| Unlock after PBKDF2 | One figure per row size and count: the median of Enclave derivation + read + trial-decrypt + decode over 5 passes, with the first pass beside it. **Marked WITHIN or OVER the limit decided 2026-11-24 (§1.5, "Fallback"): at most 500 ms at 1,000 contacts and 2,000 ms at 5,000.** 100 contacts has no limit. A summary after the stores lists every row size and count with its figure and mark | The decision to keep trial-decrypting every row, or to add the fallback |
| Where the time goes | The share of read, trial-decrypt and decode in each figure, and the largest one ("mostly reading", "mostly decrypting" or "mostly decoding" when it is over half, else "largest share"). The summary counts the largest phase over the rows that have a limit | The next step: decoding is what lazy decoding removes; a 16-byte locator tag per row cuts reading and decrypting only by the rows that aren't this space's (noise rows and other spaces' rows) |
| Photo by ID | 30 fetches of one photo row from the contact table by its ID, with and without decrypting it | Photo display latency, §1.5 |
| Vault | 20 entries of 4 KB and 200 noise rows; reading and trial-decrypting all of them | The vault's unlock cost, §1.5 |
| WAL after closing | Whether `-wal` and `-shm` still exist after the last connection closes, with and without a `wal_checkpoint(TRUNCATE)` first, and Apple's SQLite defaults (`journal_mode`, `secure_delete`, whether the WAL persists) | §8 item 26's second test and decision 26: the store must delete its `-wal` on close, and a persistent WAL default would need turning off |

The mock contact is about 8 KB of JSON at every row size, and decode parses that, not the padding, so a contact
that fills a 48–64 KB row would decode slower than these figures: the report prints the JSON size. The row size
counts the plaintext, so a sealed row is 28 bytes more (AES-GCM's nonce and tag).

**Disk and memory.** The largest table, 64 KB rows at 5,000 contacts, is 11,000 rows and about 0.7 GB in a
temporary file; the table is written in chunks and read through a cursor, so memory stays at a few rows. Each
table is deleted when its measurement ends, so only one exists at a time. Check that the phone has 1 GB free.

Every store is opened with `PRAGMA secure_delete=ON` and `PRAGMA journal_mode=WAL`, and the report says so. The
contact table's first pass is the closest it gets to a cold start: the OS page cache can't be dropped from an app.
All keys and rows are mock and random; AES-GCM's cost does not depend on them.

## What it does not do

- It never reads or writes Occulta's container, keychain, App Groups or `Manager.Key`.
- It writes nothing outside its temporary directory, and removes a directory left by an earlier killed run when it
  starts.
- It does not measure writes, shreds or the migration; those wait for the store layer.

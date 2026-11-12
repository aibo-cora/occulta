# Known limitations, Secure Mode scope (recon-1e, commit 87d9bf11)

Format: `ID — status — limitation — source`. `bugs.md` = `Docs/Features/Secure Mode/bugs.md`; `FTA` = `Occulta/Features/SecureMode/forensic-trace-avoidance.md`; `REG` = main-checkout `Docs/Audit/OPEN_LIMITATIONS.md`; `PA` = `Docs/v2.0.0/PROTECTION_ASSESSMENT.md`; `PR` = `Docs/v2.0.0/PASSPHRASE_ROLLOUT.md`. Fixed items excluded. "Open-ND" = doc says "open, needs a decision" (not accepted).

## A. Coercer at a duress depth

1. Bug 103 / 104 — ACCEPTED (decided 2026-08-13) — an inbound bundle or identity challenge from a hidden contact renders that contact's name, phone, email; rejecting instead is itself an oracle. — bugs.md:8504, :8671; Docs/Bugs/v1.10.0/Non-Safe-Sender-Rejection-Is-A-Duress-Detection-Oracle.md:3, :336-394 (FTA C3 still says "Open, unscoped": stale).
2. Non-Safe-Sender doc mitigations — Open-ND ("Neither is an accepted limitation") — two mitigations to item 1 worth building, not built. — same doc:546-553, :632.
3. Bug 173 — Open-ND, awaiting owner — a coercer can Approve a hidden contact's identity challenge; the app signs and answers, the contact sees "verified". Same as REG K R5. — bugs.md:14198-14240.
4. Bug 178 residual — Open, not fixed — a group draft typed at a duress depth is not scoped to it; owner sees it at depth 0. Groups are deliberately not depth-filtered. — bugs.md:14473, :14497.
5. REG §I content richness — ACCEPTED 2026-09-07 — a thin or empty duress depth (vault, BEK/trustees, custody, groups) is recognisable by a coercer with outside knowledge or who compares depths. — REG section I; PA "Residuals"; Group Messaging SPEC.md:192.
6. FTA S8 — ACCEPTED (design) — with forced Face ID a coercer sees "No entries yet" while the DB holds N vault rows. — FTA "S8" section.
7. Bug 62 residual and Gap 3 — residual ACCEPTED low-probability; Gap 3 Open (blocked by Bug 13 conflict) — a coercer proposing the master PIN as "duress PIN" is later routed to depth 0 unknowingly; targeted wipe unbuilt. — bugs.md:1940, :2105, :2160-2172.
8. Bug 62 Gap 2 — Open — no attempt limit on activation probes; v2.0 plan removes the collision check. — bugs.md:2062; Docs/v2.0.0/README.md:50; PR:632.
9. Erase All Data — PARTIAL (confirm dialog only) — row visibility at a duress depth and a separate panic-wipe entry undecided. — Docs/Bugs/v1.10.0/Erase-All-Data-Reachable-By-Coercer-With-Zero-Confirmation.md:3, :103-106.
10. Message Ban — design note — a coercer holding the unlocked device can issue bans. — Docs/Features/Message Ban/FINDINGS.md:149.
11. Bug 99 residual — ACCEPTED — trustees left visible at a duress depth count toward a restore there; "Recovery in progress" shown at duress though the result lands at depth 0. — bugs.md:7632, :6378.
12. Bug 120 — Open-ND — rows of a duress depth never change when others are written, so comparing images with a surrendered phrase shows another depth is in use; not closable with per-depth keys. — bugs.md:10421; PA "Repeated images".
13. Bug 106 — ACCEPTED tradeoff — vault/BEK arrays share one key across depths. — bugs.md:8938-9008.
14. Bug 180 R1-R6 — Open-ND — per-depth challenge column; R4 a reply drained at the wrong depth is consumed there. — bugs.md:14603-14612; FTA S10.
15. Bug 162 — Open-ND — trustee's stored rows and piece dates still show how many depths have a backup. — bugs.md:13277-13360.
16. Bug 163 / 195 — Open-ND — a late `.replace` leaves a stale piece; re-exchange reaches only its own depth; a revoked trustee still shows confirmed. — bugs.md:13419, :14859-14864.
17. Shard custody — ACCEPTED/on hold — hidden trustee rows simply vanish; DecoyCustodian justification withdrawn. — Docs/Bugs/v1.10.0/Shard-Custody-Not-Cleaned-Up-On-Contact-Deletion.md:117, :189-199.
18. Bug 143 — ACCEPTED 2026-09-28 — a group-only trustee never confirms, export stays blocked. — bugs.md:12386.

## B. Forensic examiner

19. Bug 119 — Open (passphrase design is remedy) — device-released keys decrypt every depth under AFU extraction; PIN verifiers crack in under a second and reveal depth count. — bugs.md:10261; Docs/v2.0.0/README.md:34-38; PA "By attack".
20. S5 / Bug 13 — ACCEPTED (design) — hidden contacts stay in the DB, filtered at UI only. — FTA S5; bugs.md:241-255.
21. Bug 112 — Declined (low) — `Contact.Profile.deletionToken` nil vs non-nil is a keyless signal. — bugs.md:9592-9661; Docs/General/decisions.md:60.
22. Bug 117 — Open (low) — 50-row soft-delete eviction has no defined order. — bugs.md:10078.
23. Bug 71 / 62 Gap 1a — Open but largely moot (LayerStore removed 2026-09-10) — mtime correlation; orphan dummy blobs leaking a count. — bugs.md:2541, :2019.
24. Bug 89a, 94a — ACCEPTED residuals — scrubbed stamps differ distributionally for a with-key examiner; shard-op filler differs in `kind` spelling and `attributeID`. — bugs.md:5554, :7047.
25. Bug 101 — residual — an open-in-place `tmp/…-Inbox` copy waits for next backgrounding if killed in foreground. — bugs.md:8150.
26. FTA S10/S11 (Bug 180 R7) — Open-ND — every sealed per-contact column is re-sealed with a fresh nonce per write, so which contact's row changed, and when, is readable without a key; Bug 71 jitter not applied to contact rows. — FTA S10-S11; bugs.md:14603-14616.
27. Bug 156 / 158 / 167 — Open-ND — prekey retirement clock, dedupe on sender's clock, challenge size recognisable. — bugs.md:12963, :13070-13089, :13702-13720.
28. Bug 170 — Open-ND in part — keychain items (legacy prekey tags naming contacts, custody key) survive app deletion; per-install keys deliberately stay. — bugs.md:13820-13830.
29. Bug 171 open items — Open-ND — copied pre-reseal ciphertext stays readable to a holder of Q; no ML-KEM below iOS 26; `Contact.Profile.identifier` unchanged for address-book imports; later filler distinguishable from wrapped filler with a live Enclave; vault epoch column; share-staging legacy fallback; AppLayerConfig row created with flag off. — bugs.md:14003-14100 (:14020, :14031, :14042, :14054); PA "Residuals".
30. Bug 196 — mixed-group residual ACCEPTED by owner; K stable pseudonym, Z_OPT/history on pairing-secret column Open-ND; card fingerprint deferred. — bugs.md:15095, :15149, :14996, :15140.
31. Bug 168 — ACCEPTED 2026-10-16 — a downgraded build deletes every contact's prekey record. — bugs.md:13735.
32. Bug 196/197 — "documented, not fixed" — `rollback()` can drop a used prekey's mark; attachment unreadable until the reseal runs; Bug 197 Open for 2.1.0. — bugs.md:15385, :15437, :15443.
33. FTA O1 / O2 — residual accepted — pre-fix keyboard lexicon words remain; pasteboard readable 120 s. — FTA "O1", "O2".
34. FTA U5d — Still open — app-switcher animation frame is captured before any callback (KTX file part closed). — FTA "U5d".
35. PA residuals — Open-ND/unfixable — unopened classical-only messages, transport records, prekey changes across images, attribution for non-upgraded pairs, having Occulta installed. — PA "Residuals no stage closes".
36. PR design — Open-ND — adding/removing a depth shows across images; lock-present stays visible through the verifier scalar. — PR:219-221, :374.

## C. Other

37. Bug 81 — ACCEPTED — fail-closed signature gate blocks 1.9.x contacts; single refusal string kept to avoid a duress oracle. — bugs.md:3651, :3730-3747.
38. Bug 82a/82b/83 — Open (availability). — bugs.md:3902, :4161.
39. Bug 92 — Open — an exported backup opens for anyone holding its backup key. — bugs.md:5786.
40. Bug 91, 121 — Open — `Contact.Draft` rules unwritten; `Backup.rotate()` unreachable. — bugs.md:5686, :10522.
41. REG B/D — Open — no MCSession peer authentication (§3.2); identifier falls open to raw UUID (§4.1); silent `deleteAllKeys`; no `.occ` fuzzing or share-extension tests. — REG B, D.
42. SECURE_MODE_DECRYPT_CONTRACT — ACCEPTED — `VaultGlobalTrustees`, `Vault+ShardSetup`, `Vault+Tab` use empty-name fallback ("acceptable" rows); decrypt-fail timing not normalised; `String.decrypt()` returns "" by contract. — SECURE_MODE_DECRYPT_CONTRACT.md Contact Display Paths, Timing.
43. USER_GUIDE.md — Open (REG E) — describes PIN as an encryption key and names law enforcement. — USER_GUIDE.md:100, :157; REG E.

## Q1. `deactivateSecureMode` at depth 1 lands at depth 0; "Deactivate Protection" at `coercerBaseDepth`

Partly documented, never as a coercer-exploitable observable.
- Code: `Manager+Security.swift:488` `newDepth = max(0, depth - 1)`; :489-491 clears `sealedDuressVerifier` when 0; comment :486-487 "depth <= 1 has nowhere shallower than 0 to land — that is also a full deactivation". Gate `Settings.swift:202-207`: `... (currentDepth == 0 || currentDepth == coercerBaseDepth) && pinEnabled`.
- Bug 45 (bugs.md:1065-1077): button at a duress depth was Critical because it confirms Secure Mode; hidden except depth 0.
- Bug 47 (bugs.md:1163-1196): deliberately re-shows it at `coercerBaseDepth = N+1`. scenarios.md:249 (§6.4) "intentionally unreachable"; :254 (§6.5) visible at N+1, "returns to the pre-coercer-activation state". Message Ban FINDINGS:149: absence would be the tell.
- Bugs 58/61 (bugs.md:1739-1747, :1923): activating from depth 1 sets `coercerBaseDepth = 1`, state `.normal`, button shows at depth 1; framed as the real user.
- Bug 111 (bugs.md:9528-9590): one-level pop, `coercerBaseDepth = newDepth`; button reachable at every intermediate depth. Depth 1 to 0 not examined for a coercer. decisions.md:66, bugs.md:10213 say "always returns to depth 0 or 1".
- v2.0 reverses it: decisions.md ~:1117-1135 (decided 2026-10-19) "No depth removes itself"; PR:436 replaces today's `coercerBaseDepth` rule. Acknowledged only as a rule being replaced, not as a limitation. A report of this is a candidate, not a known item.

## Q2. `sealedDuressVerifier` nil vs non-nil as a tell

Not discussed as a forensic tell anywhere.
- Plain `Data?` column (`AppLayerConfig+Model.swift:22-23`), the live "Secure Mode active" test (`Settings.swift:198`, `Manager+Security.swift:86`, :333, :453).
- `SecureMode+RotationContract.md:34` (I7): the scalars "are nil when those features are not configured"; argues only that the row's existence is no tell.
- FTA K1/K2 argue opacity and presence for `persistedDepth`/`pinEnabledPerDepth` only ("field absence vs. presence would distinguish ..."); the scalars are not covered.
- PR:219 (**Open, needs a decision**) and :374 concede only that the NORMAL scalar shows whether a lock exists.
- bugs.md:14022-14031 (Bug 171 stage 3) wraps the non-nil scalars and slots but does not address nil-ness. Nearest precedents: Bug 112 (declined), Bug 119 (Open).

## Staleness

- FTA C3 table says "Open, unscoped"; per-issue doc is Fixed with accepted residual, Bugs 103/104 closed as accepted.
- FTA K1 "all opaque Data" does not hold for the two scalar verifier columns.
- scenarios.md §6.1 (key rotation, blob restore, `.pinOnly`), §1.6 describe removed machinery; §6.4 "Only depth 0 can deactivate" contradicts Bugs 47/58/61/111 and the code.
- plan.md Steps 3+ and `SecureMode+RotationContract.md` describe removed blob/rotation code (plan.md:3-12 says so); decisions.md:66 predates Bug 111.
- REG sections A-H are from August (`release/v1.10.3`); Bugs 70/71/72/62 Gap 1a concern the removed LayerStore. Section K is current. REG is gitignored.
- bugs.md Bug 13 carries its own "Stale, 2026-09-11" note.

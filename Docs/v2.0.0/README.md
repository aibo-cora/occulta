# v2.0.0 — Hardening Plan

**Status:** Proposed, 2026-09-30. Nothing here is decided or scheduled. These are findings from a threat
review of `develop` at `3319fd7` (v1.11.1), written up so the release can be planned against them.

**Design spec for the core change:**
[`PASSPHRASE_LAYER_KEYS.md`](../../Occulta/Features/SecureMode/PASSPHRASE_LAYER_KEYS.md). Steps 1–5 in
this folder are that document's design, restated as release steps. Everything else here surrounds it:
the other hardening steps, how to stage the release, and what protection each stage actually buys. Where
the two disagree, the spec owns the cryptographic design and this folder owns sequencing.

## Documents

| File | Answers |
|---|---|
| [HARDENING_STEPS.md](HARDENING_STEPS.md) | What to change, and why each change is needed |
| [ROLLOUT_PLAN.md](ROLLOUT_PLAN.md) | How to ship it in stages without creating a new tell |
| [PROTECTION_ASSESSMENT.md](PROTECTION_ASSESSMENT.md) | What an adversary gets today, and after every stage |

## Threat model

The adversary assumed throughout has state-level resources. They can:

- take physical possession of the phone;
- obtain or recover the device passcode — compelled, observed, or brute-forced;
- run code on the device with commercial extraction tools (Cellebrite/GrayKey class);
- image the device more than once over time;
- keep a copy of every `.occ` file sent, including copies held by third-party transports such as iCloud
  Messages backups;
- compel the user to unlock the app;
- hold an iOS or Secure Enclave exploit.

**Where that leaves the app today.** Against this adversary, Occulta adds no protection beyond the
device passcode. Every Occulta key except the vault's is released by an unlocked device alone
(`.privateKeyUsage`, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`), and the vault key accepts the
device passcode as an alternative to Face ID. With the passcode and code execution, every depth
decrypts. The Secure Mode PIN verifiers also crack in under a second, which reveals how many depths
exist (`bugs.md` Bug 119; threat review of 2026-09-29, recorded under Bug 119 and in the spec's §1, §3
and §4).

## Related tracked items

The central trackers stay canonical: [`bugs.md`](../Features/Secure%20Mode/bugs.md) for bugs,
[`OPEN_LIMITATIONS.md`](../Audit/OPEN_LIMITATIONS.md) for the register. This is the subset the plan
depends on.

| Item | Summary | Status | Plan step |
|---|---|---|---|
| Bug 62 | `pinCollision` PIN oracle; Gap 2 (no attempt limit) and Gap 1a still open | Open | 1 (removes the collision check entirely) |
| Bug 82 | Identity-key change strands earlier messages; split 82a/82b | Open (82a P1, 82b P2) | 6 (the measurement that fallback fires first in each direction) |
| Bug 109 | Per-depth keys leave an authentication-failure tell on rows the key doesn't own | Closed moot, 2026-09-10 | 3 (returns if per-depth keys ship without it) |
| Bug 119 | Vault key is device-level; one key opens every depth under AFU | Open | 1, 2 |
| Bug 120 | Write frequency across snapshots reveals the real depth | Open | 4 |
| Bug 123 | Small sealed fields share one AAD, so ciphertext splices between rows | Closed, subsumed into 119 | 5 |
| Register §B §3.2 | No `MCSession` peer authentication | P1 | 8 |
| Register C2 | Hybrid local DB key re-derived per operation; a cache is planned | P1 | 13 (the cache must follow its rule) |
| Register D1 | Distribution-build signing checks never run | P0 as last recorded | 14 |
| Register D4 | No independent human review | P1 | 15 |
| Register D5, D6 | No share-extension tests; no fuzzing of `.occ` decoding | P2 | 12 |
| Register §E | Language risk; `USER_GUIDE.md` overclaims and names authorities | Tier 3 P1 | 11 |
| Register §I | A duress depth's content can look thin next to the real one | Accepted, 2026-09-07 | Residual; see the assessment |
| Spec §2, message keys | Prekey tags name contacts; classical-only modes open with the passcode alone | Decided, 2026-10-04; open items listed in step 17 | 17 |
| Bugs 155–160 | Prekey batch lifecycle: needless batches, keys never pruned, clock-based dedupe, untested trigger | Open | 6, 17 (via [Prekey Continuity](../Features/Prekey%20Continuity/DESIGN.md), targeted at v2.0.0 on 2026-10-06; D1–D6, D8, D9 decided, D7 open. D9 supersedes 17b for prekeys) |

Steps 6, 7, 10, 13, 15, 16 and 17 are not tracked anywhere else yet.

## Vocabulary

Written with `OPEN_LIMITATIONS.md` §E in mind: "adversary" rather than a named authority, and no
framing of the product against any institution. Keep new material in this folder to the same standard.

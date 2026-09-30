# v2.0.0 — Protection Assessment

**Status:** Assessment, 2026-09-30, against the threat model in [README.md](README.md). The "after"
column describes a design that isn't built yet. See "How much to trust this" before relying on it.
Step numbers refer to [HARDENING_STEPS.md](HARDENING_STEPS.md). Per-stage progression is in
[ROLLOUT_PLAN.md](ROLLOUT_PLAN.md).

## Short answer

Once every stage is built, a seized phone gives a well-resourced adversary only what the user chooses to
surrender. That holds even with the device passcode, and even with a Secure Enclave break. Today the same
phone gives them everything once they have the passcode.

What no stage fixes: an implant on the phone while it's in use, contacts' phones, and the fact that the
user has Occulta at all. Once the cryptography holds, those become the adversary's cheapest routes.

## By attack

| Attack | Today | After all stages |
|---|---|---|
| **Phone seized while powered off (before first unlock)** | Safe if the device passcode is strong. A 6-digit numeric passcode takes about a day once a tool gets past the Enclave's retry limits. | Same, plus the phrase. |
| **Seized after first unlock, screen locked, no passcode** | Needs an iOS exploit. The store is `FileProtectionType.complete` (`OccultaApp.swift:74`, `:1213`) and every key is `WhenUnlockedThisDeviceOnly`, so everything still depends on the passcode. | Same. |
| **Passcode obtained, plus forensic extraction** | **Everything:** every depth, the vault, and how many depths exist. | Only what the surrendered phrase opens. Other depths sit behind ~90 bits, and every guess costs a Secure Enclave call on that phone. |
| **Secure Enclave broken (hardware exploit)** | Everything, with or without the passcode. | The phrases hold: about 27,000 years to crack even with the Bitcoin network's entire SHA-256 throughput (7 words, PBKDF2). |
| **User compelled to unlock Occulta in person** | The duress depth looks plausible, but a later forensic examination contradicts it. | The examination matches what the user showed. What remains is register §I, below. |
| **Device imaged repeatedly over time** | Moot, since everything is readable. | Comparing images shows that Occulta is used, not which depth. |
| **Messages copied in transit, phone seized later** | The first message each way, and about 1 in 16 after, can be opened with the phone. Opened forward-secret messages can't. | Only unopened messages (see residuals). Pairs without post-quantum are recorded now to decrypt later, until 7b. |
| **Implant on the phone while in use (Pegasus-class)** | Everything. | Everything. Dropping keys in the background (13) shortens the window. Only Apple's Lockdown Mode reduces the chance of infection. |
| **A contact's phone seized** | The user's identity, the relationship, and anything the contact kept. | Same, limited only by the contact's own passcode and phrase. |
| **Establishing that the user has Occulta, and when it's used** | Apple's download records, the OS's app-usage records, and the radio broadcast during exchanges. | The broadcast window is smaller (10). The rest doesn't change. |
| **Malicious update (account stolen or developer compelled)** | Everything. | Stealing the account gets harder (15). Nothing stops a compelled developer. |

**A strength already in place:** Occulta keeps no message history. Message Persistence is exploratory
and was never built (`Docs/Features/Message Persistence/FINDINGS.md`), so read messages leave nothing
inside the app to extract.

## Residuals no stage closes

- **An implant on the unlocked phone.** It reads the screen, the phrase as it is entered, and keys in
  memory. This is the ceiling for any app.
- **Contacts' phones.** Each relationship is only as protected as the less careful side.
- **Having Occulta installed, and when it's used.** Download history and the OS's usage records exist
  outside the app.
- **Unopened messages.** These include messages from contacts hidden at other depths. The prekeys and
  the identity key that open them are device keys shared across depths, and no step moves them under a
  phrase. This is not yet analysed, and it is a candidate question for the spec.
- **Register §I, accepted 2026-09-07.** A coercer who already knows what should be there, or who makes
  the user open several depths and compares them, can still see that a duress depth is thin.
- **A compelled developer.** Account hardening stops theft, not compulsion.

## Where a capable adversary goes next

With the cryptography holding, the cheapest routes are:
- infect the phone while it's unlocked;
- seize the least careful contact's phone;
- compel the user, if they already suspect there are hidden depths;
- lean on the developer.

The app can narrow the first and last. It can't close any of them.

## How much to trust this

The "after" column is a target, not a guarantee, until all of these change:
- The spec's §2 (how one row opens under every depth's key) is unresolved.
- No independent person has reviewed the code (register D4).
- The file decoders have never been fuzzed (register D6).

Against an adversary who has the device passcode today, Occulta adds no protection beyond the passcode
itself.

## Figures used

| Figure | Source |
|---|---|
| Device passcode: about 80 ms per attempt, so 10⁶ × 80 ms ≈ 22 h worst case for 6 digits | Apple Platform Security guide, passcode key derivation calibration |
| Secure Mode PIN verifiers crack in under a second after extraction | `bugs.md` Bug 119, threat review of 2026-09-29 |
| 7 diceware words ≈ 90.5 bits; ~27,000 years at the Bitcoin network's SHA-256 scale with PBKDF2 | Spec §4 table, order of magnitude, assumptions stated there |
| Fallback fires first in each direction, then roughly 1 in 16 | `OPEN_LIMITATIONS.md` note on 82a (`defaultBatchSize` 15, no prekeys in the exchange) |
| ML-KEM only on iOS 26+ | `CLAUDE.md`; `PQProvider` availability gate |

# v2.0.0 — Protection Assessment

**Status:** Assessment, 2026-09-30, against the threat model in [README.md](README.md). The "after"
column describes a design that isn't built yet. See "How much to trust this" before relying on it.
Step numbers refer to [HARDENING_STEPS.md](HARDENING_STEPS.md). Per-stage progression is in
[ROLLOUT_PLAN.md](ROLLOUT_PLAN.md).

## Short answer

Once every stage is built, a seized phone gives a well-resourced adversary only what the user chooses to
surrender. That holds even with the device passcode, and even with a Secure Enclave break. Today the same
phone gives them everything once they have the passcode.

One exception, found 2026-10-15: an adversary who imaged the phone earlier and later gets a duress phrase
can tell that another depth exists and is in use (step 4, open, needs a decision).

What no stage fixes: an implant on the phone while it's in use, contacts' phones, the transport's records
of who exchanged files with whom, and the fact that the user has Occulta at all. Once the cryptography holds, those become the adversary's cheapest routes.

## By attack

| Attack | Today | After all stages |
|---|---|---|
| **Phone seized while powered off (before first unlock)** | Safe if the device passcode is strong. A 6-digit numeric passcode takes about a day once a tool gets past the Enclave's retry limits. | Same, plus the phrase. |
| **Seized after first unlock, screen locked, no passcode** | Needs an iOS exploit. The store is `FileProtectionType.complete` (`OccultaApp.swift:74`, `:1213`) and every key is `WhenUnlockedThisDeviceOnly`, so everything still depends on the passcode. | Same. |
| **Passcode obtained, plus forensic extraction** | **Everything:** every depth, the vault, and how many depths exist. | Only what the surrendered phrase opens. Other depths sit behind ~90 bits. The design says every guess costs a Secure Enclave call on that phone; as designed it doesn't, and the Bug 171 fix (2.0.0) makes the Enclave term of the keys that exist today real but one call per unlock, not per guess, so only the ~90 bits and the KDF hold the line. Recommended: drop the per-guess requirement and keep the `ECDH(d, P)` term (D2); open, needs a decision (`bugs.md` Bug 171). |
| **Secure Enclave broken (hardware exploit)** | Everything, with or without the passcode. | The phrases hold: about 27,000 years to crack even with the Bitcoin network's entire SHA-256 throughput (7 words, PBKDF2). |
| **User compelled to unlock Occulta in person** | The duress depth looks plausible, but a later forensic examination contradicts it. | The examination of one image matches what the user showed. What remains is register §I, below. An earlier image contradicts it (next row). |
| **Device imaged repeatedly over time** | Moot, since everything is readable. | Without a phrase, comparing images shows that Occulta is used, not which depth. With a surrendered duress phrase, rows it can't open that changed between images show that another depth exists and is in use (step 4; open, needs a decision, 2026-10-15). |
| **Messages copied in transit, phone seized later** | The first message each way, and about 1 in 16 after, can be opened with the phone. Opened forward-secret messages can't. | Only unopened messages from contacts the surrendered depth shows (17), classical-only messages from senders on old versions, and messages to a new contact before their first reply, which use the long-term key while step 6 is deferred (open; the compose indicator warns). Pairs without post-quantum are recorded now to decrypt later, until 7b. |
| **Keychain listed after a duress phrase is surrendered** | Not needed, since everything is readable. | Without 17: the hidden contacts and how often each messages. With 17, one image: a total that a few hidden contacts can hide in. Repeated images: prekeys appearing and disappearing that the surrendered depth can't account for (open). |
| **Transport records** (who sent which `.occ` to whom, and when) | An ongoing exchange with any contact. | Same. An ongoing exchange with a contact the surrendered depth doesn't show can't pass as a deleted contact. |
| **Implant on the phone while in use (Pegasus-class)** | Everything. | Everything. Dropping keys in the background (13) shortens the window. Only Apple's Lockdown Mode reduces the chance of infection. |
| **A contact's phone seized** | The user's identity, the relationship, and anything the contact kept. | Same, limited only by the contact's own passcode and phrase. |
| **Establishing that the user has Occulta, and when it's used** | Apple's download records, the OS's app-usage records, and the radio broadcast during exchanges. | The broadcast window is smaller (10). The rest doesn't change. The mDNS announcement on the joined Wi-Fi network, which that network's equipment may log, is open (10). |
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
- **Unopened messages, narrowed by step 17 (2026-10-04).** Once 17 ships, a hidden contact's message
  needs a secret from that contact's record. Two cases still open with the passcode alone:
  classical-only messages from senders on old versions, and anything sent before the pair upgraded.
  Open, needs a decision.
- **The transport's records.** Messages history and its backups show an ongoing exchange of `.occ` files
  with a hidden contact. The app can't hide this. Step 16's guidance has to cover it. Open, needs a
  decision.
- **Prekey changes across repeated images.** Keys appear and disappear that the surrendered depth can't
  account for. Replacing dummies to hide this was rejected (step 17). Open, needs a decision. *Changed by
  D9, 2026-10-06* ([Prekey Continuity §9](../Features/Prekey%20Continuity/DESIGN.md)): prekeys move into the
  contact record, so their changes become row writes, covered by step 4. This applies to legacy keychain
  prekeys until they retire, and stays open until step 4 is shown to cover those writes.
- **Attribution of files, closed by 17a for upgraded pairs.** Today the sender fingerprint lets anyone
  with the user's public key, which every contact has, tell which `.occ` files the user sent. 17a keys it
  with the per-contact secret. Files to contacts who haven't upgraded, and group files with any such
  recipient, stay attributable. Open, needs a decision.
- **Repeated images with a surrendered phrase, found 2026-10-15.** Rows the surrendered depth can't open
  change during real use, and nothing that depth does could change them. Closing it needs re-randomisable
  encryption, which CryptoKit doesn't offer, or an append-only redesign of storage (spec §2). Open, needs a
  decision. Step 16's guidance has to cover it.
- **Register §I, accepted 2026-09-07.** A coercer who already knows what should be there, or who makes
  the user open several depths and compares them, can still see that a duress depth is thin.
- **A compelled developer.** Account hardening stops theft, not compulsion.
- **The Enclave half of every key built as `ECDH(Enclave key, G)`, found 2026-10-21; fixed in 2.0.0 for the keys that exist,
  with what stays open.** The output was a function of the key's public point, so it added no secret. That covered the local
  DB key, the vault key, the shard custody and restore keys, the Secure Mode PIN key and the share staging key, and covers the
  planned layer keys' "device-binding" half. Each is now `HKDF(ECDH(Enclave key, P) ‖ [ML-KEM secret ‖] r_tier)` with P a
  point nobody knows the discrete log of, so it needs the Enclave key and a Keychain secret of its access tier, and on iOS 26+
  an Enclave ML-KEM key. What is still open, each needs a decision (`bugs.md` Bug 171):
  - ciphertext copied before the reseal moved it stays readable to a holder of Q, and so do images taken while a device was
    classical (below iOS 26, no ML-KEM term): no reseal protects what is already copied;
  - below iOS 26 a keychain dump that holds Q and the tier secret, analysed later with a quantum computer;
  - whether an image alone yields Q: no cleartext column does on the Simulator; a device answer needs extraction tooling;
  - `Contact.Profile.identifier` is left byte-identical, so for contacts imported from the address book a holder of Q can
    link each one to its entry until the passphrase migration;
  - the vault's per-entry keys stay under the legacy key until the first unlock after the upgrade (D8);
  - the planted-session residual of share staging while its legacy fallback exists, and a reseal that stopped partway over a
    later launch that aborts before writing;
  - the per-guess requirement of the layer keys (D2), recommended to be dropped.

## Where a capable adversary goes next

With the cryptography holding, the cheapest routes are:
- infect the phone while it's unlocked;
- seize the least careful contact's phone;
- compel the user, if they already suspect there are hidden depths;
- lean on the developer.

The app can narrow the first and last. It can't close any of them.

## How much to trust this

The "after" column is a target, not a guarantee, until all of these change:
- The spec's §2 (how rows are stored under per-depth keys) has a design proposed on 2026-10-15, not
  decided.
- No independent person has reviewed the code (register D4).
- The file decoders have never been fuzzed (register D6).
- Any claim here that a key needs the Enclave, a biometric, or "this device" holds for the forms after Bug 171
  (`ECDH(Enclave key, P)` with a Keychain secret per tier) and not for the legacy `ECDH(Enclave key, G)`, which
  Bug 171 found to be a function of a public value. The fix is built and tested on the Simulator; its real vault access
  control, the cross-process share-staging check on a phone, and device timings are not yet done (open, needs a device).
  The per-guess Enclave claim for the unreleased layer keys is not met by it: recommended to be dropped, open, needs a decision (D2).

Against an adversary who has the device passcode today, Occulta adds no protection beyond the passcode
itself.

## Figures used

| Figure | Source |
|---|---|
| Device passcode: about 80 ms per attempt, so 10⁶ × 80 ms ≈ 22 h worst case for 6 digits | Apple Platform Security guide, passcode key derivation calibration |
| Secure Mode PIN verifiers crack in under a second after extraction | `bugs.md` Bug 119, threat review of 2026-09-29 |
| 7 diceware words ≈ 90.5 bits; ~27,000 years at the Bitcoin network's SHA-256 scale with PBKDF2 | Spec §4 table, order of magnitude, assumptions stated there |
| Fallback fires first in each direction, then roughly 1 in 16 | `OPEN_LIMITATIONS.md` note on 82a (`defaultBatchSize` 15, no prekeys in the exchange) |
| ML-KEM only on iOS 26+ | `CLAUDE.md`; `PostQuantumProvider` availability gate |

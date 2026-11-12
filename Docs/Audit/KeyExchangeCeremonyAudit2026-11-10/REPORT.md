# Key exchange ceremony audit, 2026-11-10

Code and security audit of how a contact's keys are established, saved, rotated and retired on the 2.0.1 line.

- **Commit:** `87d9bf11d4d8190f19da0cad8ac12aaaba4a6bb3` (`v2.0.1/version-bump`). Every line number below is at that commit.
- **Method:** the `occulta-security-audit` skill, `quick` profile, source reading only. Nothing was built or run, so every finding is a **lead** (`needs_validation`) until a test proves it. Severities are **proposed**, on the scale in the skill's threat model.
- **Run status:** `incomplete`. See "Deviations and what was not covered" at the end.
- **Filed:** Bugs 198–206 in `Docs/Features/Secure Mode/bugs.md`, all `unconfirmed`. Hunter and verifier write-ups are in `agents/`.

## Findings, ranked

| # | Bug | Proposed severity | Finding | Verified by |
|---|---|---|---|---|
| KX-1 | 198 | **High** | A man in the middle of the Multipeer session can make both phones show the same verification words: nothing commits his last contribution, so 5 words give about 32 bits, not 64 | verifier, from source |
| KX-2 | 199 | **Medium** | The ML-KEM key can be removed from an exchange in transit and the words still match; nothing on screen says the phone offered one and got none back | verifier, from source |
| KX-3 | 200 | **Low** | Teardown does not fence callbacks already queued: a late connect can crash the app, a late ranging update re-arms the watchdog, and the classical path can present a confirmation after the exchange timed out | verifier, from source (all four parts hold) |
| KX-4 | 201 | **Low** | Revoke leaves the revoked pairing's routing key and Enclave pair-key blobs on its row, and a later re-pair does not clear them | parent, from source |
| KX-5 | 202 | **Low** (latent) | `save(contact:)` installs whatever keys a `Contact.Draft` carries, and the unused `Import` screen decodes drafts from a received file: one call away from a key that no in-person exchange made | parent, from source |
| CD-1 | 203 | **Medium** | A classical-only in-person exchange skips the card meeting check, so a card conversation that was intercepted or forged ends as Verified with no warning | hunter; parent re-read the cited lines |
| PK-1 | 204 | **Medium** | A contact's prekey batch is accepted without checking its keys are curve points; one bad batch stops every send to that contact and to any group they are in | hunter; parent re-read the cited lines |
| PK-2 | 205 | **Low** | A send that fails after taking a contact's one-time key still uses the key up | hunter; parent re-read the cited lines |
| CD-2 | 206 | **Low** | The time to reject an unknown-sender file grows with the number of unexpired issued cards at every depth, hidden ones included | hunter; parent re-read the cited lines |

Ranked: KX-1, then KX-2, CD-1 and PK-1, then the Low ones in the order KX-3, PK-2, KX-4, CD-2, KX-5.

Known items that this audit met again and does not re-file are listed under "Known items".

---

## KX-1 (Bug 198): the verification words can be made to match by a man in the middle

**Proposed severity: High.** Whoever wins the Multipeer connection on both phones ends up holding both pairings, reads and forges everything the two people send afterwards, and both confirmation screens show the same five words. It needs an attacker in radio range at the ceremony and a few GPU-minutes of hashing. It is rated High and not Critical only because it needs presence at the exchange.

### What the design relies on

The Multipeer session authenticates nobody: `MCSession(peer:securityIdentity: nil, encryptionPreference: .required)` (`Exchange+Manager.swift:182`), the advertiser accepts every invitation (`:915`), the browser invites every peer it finds (`:902`), and the first peer to reach `.connected` is pinned (`:479-487`). The 25 cm gate checks that *some* device whose discovery token the pinned peer sent is close (`:783-792`); the token is not bound to the Multipeer peer. So an attacker M who is pinned by both phones passes Bob's real token to Alice and Alice's to Bob, the two real phones range each other and the gate opens, while every identity message goes through M.

The docs say so, and name the one defence: "The defence against an active MITM on that channel is the Diceware SAS, and nothing else" (`Docs/Features/Remote Key Exchange/FINDINGS.md:24`), and Bug 196's safety invariant, "What authenticates the exchange is the words both people compare". The same documents call the words "not grindable" because "each side's nonce [is] committed in the discovery message before any identity key is seen" (`FINDINGS.md:41`, `:168`; the comment on `generateExchangeNonce`, `Key+Manager.swift:1880`).

### What happens

The nonce is *sent*, not committed, and it is not the last thing the attacker contributes. A short comparison string is only as strong as its length if the party who speaks last was bound to its value before it saw the other side's. Here it is not:

1. M uses a Multipeer display name that sorts above both victims' (names are UUID strings; `"~"` works). Both victims are then the initiator (`:488`), and each sends M its nonce at connect (`:507-514`) and its whole identity message — identity key, ML-KEM key, `pairing` field — three seconds after the gate opens (`:801-809`), before M has sent an identity message of its own.
2. M answers each with an identity message that has **no `encapsulationKey`**. Both victims take the classical path (`:649-675`). With pair keys the words are `RoutingKey.wordsKey(pk, ik, salt, nil, nonces, transcript)` (`PairwiseDerivation.swift:131-138`, called from `KeyExchange.swift:288-295`). M knows every input: `pk` and `ik` are ECDH with keys M made, the salt is two public keys, both nonces are known, and the transcript is the two `pairing` fields.
3. M still has values it can change after seeing all of that. Its own nonce is not fixed: `self.peerNonce = nonce` runs on every discovery message with no check on the state of the exchange (`:566-568`), so M sends a second discovery message with a new nonce just before its identity message. The nonces enter only the HKDF info, so a trial is about 30 SHA-256 compressions and no curve operation. (The verifier found this route; the hunter's was the prekey batch's `generatedAt` and `id`, which reach the transcript through `batchDigest`, `PairwiseDerivation.swift:71-90`, and which `PairingOffer.accepted` does not constrain, `PairingOffer.swift:162-181`. Both work.)
4. M needs Alice's words to equal Bob's, and controls a free value on each side. That is a collision search between two lists: about 2^32.3 candidates per side for 64.6 bits, roughly 2^38 SHA-256 compressions in all, a few core-hours on CPUs and about a minute on one GPU. The table is tens of gigabytes, or nothing with a distinguished-point search.
5. Nothing times the victims out meanwhile. A phone waiting in `.waitingForPeerIdentity` has no deadline of its own; the only timer is the 30-second watchdog, which every ranging update resets (`:777`), and the two real phones keep ranging each other.
6. M sends the two chosen identity messages. Both phones reach the confirmation screen with the same five words. Each saves M's identity and pair keys as the other person's.

Variants:

- **Hybrid, nothing stripped.** M is the responder, so it also sends the last ML-KEM ciphertext (`:745-765`). Each trial is then one ML-KEM-1024 encapsulation, about 2^33 in all: around a hundred core-hours, seconds for the adversary in the threat model. M does not need this path, because step 2 is always available.
- **No pair keys, no ML-KEM** (a 2.0.0 peer, or both stripped). The words are `createSharedSecret(using: classicalKey)` (`KeyExchange.swift:305`): the identity ECDH alone, no nonces. The search can be done ahead of time by anyone who knows both people's public identity keys, which every contact of both does, and reused at every exchange between them.

### What limits it

- M has to be the pinned peer on both phones. The two real phones are next to each other and both advertise and browse, so this is a race against their own connection, and M will often lose it. M can enter early (it is already advertising when a victim starts) and can try again: a phone pinned to the wrong peer shows an ordinary "Didn't connect" after 30 seconds and the people start over. How often M wins was not measured; it needs two phones and a third device.
- The confirmation screen also shows two fingerprint rows (`KeyExchange.swift:165-167`). Comparing "my key" on one phone with "peer key" on the other would catch M: to make them match M would have to pass on the real identity keys, and then it could not compute the words. The screen asks only for the words to be compared (`:171`).
- The people wait in the live view while M computes. A minute is plausible; an hour is not. That bounds the hybrid variant below more than the classical one.

### Fix

Commit before reveal, the standard construction for a short comparison string:

1. In the discovery message send `SHA-256("occulta-exchange-commit-v1" ‖ nonce)` in place of the nonce. Keep the nonce secret. Accept one discovery message per exchange; a second one is ignored.
2. Run the identity and ML-KEM steps as now.
3. Add a last step: each phone sends its nonce, initiator first, only after it holds every other message of the exchange. A phone checks the peer's nonce against the commitment and fails the exchange on a mismatch.
4. Derive the words over both nonces **and a hash of every message both phones sent and received, in order** (identity keys, ML-KEM keys or their absence, ciphertexts, `pairing` fields or their absence). The transcript then also closes KX-2 and the accepted `pairing`-strip residual.
5. Give the classical path the same derivation, under its own label, so its words stop being a function of the long-term transport key and stop being the same at every exchange.

With that, M has fixed everything it sends before it learns either victim's nonce, so each attempt succeeds with probability 2^-64.6 and no search helps. A peer on an older build sends no commitment; such an exchange keeps today's strength and the screen should say the peer needs to update, the same way the pair-key note does.

Short of the protocol change, two cheap mitigations: give a waiting phone a deadline of a few seconds per step that ranging does not reset, and have the screen ask for the fingerprints to be compared too.

### Guard (test plan)

- `PairwiseDerivationTests` / a new `ExchangeWordsCommitmentTests`: a "man in the middle" fixture that knows both victims' messages and varies its own batch `generatedAt` must not be able to change a victim's words after the victim's commitment is fixed. Today the equivalent test passes the other way: two different attacker fields give two different words on the same victim, with every input known to the attacker, which is the grindable property. Runs anywhere, software keys.
- Today a second discovery message replaces `peerNonce`; after the fix it does not.
- A state-machine test (see "Test coverage") that a phone refuses a revealed nonce that does not match the commitment, and that a peer silent for longer than the step deadline ends the exchange.

---

## KX-2 (Bug 199): ML-KEM can be stripped in transit and the words still match

**Proposed severity: Medium.** **Status proposed: open, needs a decision.** It is the ML-KEM twin of a residual Bug 196 accepted for the `pairing` field, but that decision came with an on-screen note and this case has neither a note nor a decision.

### What happens

1. A man in the middle of the Multipeer session relays everything unchanged except that it removes `encapsulationKey` from both identity messages.
2. Each phone finds no peer ML-KEM key and takes the classical branch (`Exchange+Manager.swift:614-616`, `:649`). Identity keys and `pairing` fields are untouched, so both phones compute the same words: they cover the ML-KEM secrets only when there are some (`PairwiseDerivation.swift:174-183`), and nothing covers "I offered a key".
3. The words match and both people confirm. The pairing is classical: `quantumKeyMaterialEncrypted` is nil, the long-term slot key is `longTermClassicalDomain`.
4. The attacker learns nothing that day. It keeps the `.occ` files and waits for a quantum computer, which is the adversary ML-KEM is there for.

The only sign is that the small green "Quantum-resistant exchange" label is absent (`KeyExchange.swift:188-192`). For pair keys the screen says "Pair keys weren't exchanged. If both phones are on the latest version, try again." (`:197-202`); there is no such line when the phone sent an ML-KEM key and received none. A peer on iOS 18.6–25 looks the same, so the user cannot tell an old phone from interference.

`update(key:for:pairing:)` refuses a re-exchange that would lose pair keys (`Contact+Manager.swift:663-665`) but accepts one that loses ML-KEM, so the same strip also downgrades an existing hybrid pairing at a re-exchange.

### Fix

- Covered by KX-1's fix if the words' transcript includes each phone's ML-KEM key or its absence: after a strip the two phones' transcripts differ and the words do not match.
- Independently: show a note when `encapsulationKeyData != nil` and the payload has no `hybridResult`, and refuse (as `pairingWouldBeWeaker` does) a re-exchange that would replace a hybrid pairing with a classical one.

### Guard

- `KeyExchangeSaveTests`: a classical payload for a contact whose current key has quantum material is refused and the old pairing stays (fails today). `.ambientTestKeyManager`, runs anywhere.
- With KX-1's transcript: two offers that differ only in "sent an ML-KEM key, received none" derive different words.

---

## KX-3 (Bug 200): teardown does not fence callbacks that were already queued

**Proposed severity: Low.** A crash a nearby device can make more likely, and wrong screens after a cancel or timeout. No key is exposed.

Every Multipeer and NearbyInteraction callback is re-dispatched with `DispatchQueue.main.async` (`Exchange+Manager.swift:869-885`, `:923-931`). `teardownSessions()` (`:236-282`) clears the delegates, but a block already on the main queue still runs, against a manager that has been reset.

1. **Crash.** `handleSessionStateChange` passes `state == .connected`, passes the pin check because `connectedPeerID` is now nil, and force-unwraps `self.multipeerSession!` (`:488`), which is nil. A device that keeps connecting to the advertised service keeps such a block queued, so a cancel, a timeout or the `finish()` after a successful save can crash the app.
2. **Watchdog re-armed.** `handleNearbyObjectsUpdate` calls `scheduleWatchdog()` before anything else (`:777`). A late update arms a 30-second timer on a resting manager, which then sets `.timedOut` (`:295`) and makes `KeyExchange` show "Didn't connect" (`KeyExchange.swift:122-126`) for an exchange that had ended, or drop the confirmation of one started since if `start()` was not what cancelled it.
3. **A confirmation after the exchange ended.** This is the part most likely to be seen. The three classical-path tasks set `self.phase = .mlKemExchanged(payload)` after sleeping, guarded only by `guard let self` (`:668-675`, `:686-695`, `:837-844`). After `finish()` the phase comes back and `.confirming(payload)` follows: the confirmation screen appears for an exchange that was ended, and Confirm saves it. Two ordinary triggers: sending the app to the background from the live view calls `finish()` while the view stays up (`KeyExchangeLiveView.swift:90-92`), and a watchdog timeout. The other phone has usually given up, so one phone ends with a pairing the other does not hold. If the user has started a new exchange on the same manager, the old payload is confirmed inside the new one. The classical path is the normal one with a peer on iOS 18.6–25. The hybrid path does not have this; its tasks check `exchangeStatus`, which teardown clears.
4. `receivedDiscoveryTokens` is never cleared (`:40`, absent from `:262-277`), so the previous session's tokens and peers stay in the map. Inert today because a new `NISession` only ranges the token it is run with.
5. **A stale connect can pin the next exchange.** The handler never compares its `session` argument with `self.multipeerSession`. After `start()` has built a new session, a `.connected` still queued from the old one pins the new exchange to the old peer (found by the verifier). No crash in that order, only a wrong pin and a timeout.
6. The re-armed watchdog in 2 can also take down the card-check warning: after a save, `finish()` runs and the W-11 cover hangs off the confirmation view (`KeyExchange.swift:277`); a `.timedOut` 30 seconds later clears `confirmingPayload` and the cover with it.

### Fix

A session generation counter, incremented in `teardownSessions()` and captured by every dispatched block and every `Task`; each returns if it no longer matches. Replace the force-unwrap with a `guard let`, and ignore a callback whose `session` is not the current one. Clear `receivedDiscoveryTokens` and the `NISession` delegate at teardown. Move `scheduleWatchdog()` below a check that a session exists.

### Guard

`ExchangeManagerPeerPinningTests` already drives the delegate methods without radios. Add: deliver `session(_:peer:didChange: .connected)`, call `finish()`, drain the main queue — no crash, phase stays `.resting` (write after the fix: before it the test host dies, so prove the crash with a one-test `-only-testing` run). Deliver a classical identity message, call `finish()`, wait 7 seconds — phase stays `.resting` (fails today).

---

## KX-4 (Bug 201): revoke leaves the revoked pairing's keys on its row, and a re-pair does not clear them

**Proposed severity: Low.** Key material outlives the pairing it belonged to, against the rule the re-pair path states.

`update(key:for:pairing:)` overwrites a retired row's pairing column with the sealed empty state, "What a retired pairing held goes with it: its pair keys are Enclave blobs this phone could still use" (`Contact+Manager.swift:685-696`). That loop runs over rows `where held.expiredOn == nil`.

`reset(identity:)` (`:748-763`) only stamps `expiredOn`. So after **Revoke**, the row keeps the routing key and the agreement, signing and ML-DSA blobs. At the next exchange the row is already expired, the loop skips it, and it keeps them for as long as the contact exists. The same order also means:

- an identity challenge outstanding at the revoke is not dropped at the re-exchange when the new pairing is plain (`formChanges` is computed only from unexpired rows, `:689-704`);
- after a revoke a re-exchange with no pair keys is accepted, since `contact.currentKey` is nil at `:663`. That is the accepted `pairing`-strip residual, reached by a different route.

### Fix

`reset(identity:)` writes the sealed empty pairing state to the row it expires, in the same save, and drops outstanding challenges as the re-pair does. One launch pass (or the loop in `update(key:)` widened to every row) clears rows revoked before the fix; every row already holds a column of the same size, so the pass changes no size.

### Guard

`PairingLifecycleTests`: pair with pair keys, `reset(identity:)`, then read the expired row — `readablePairingState` is `.empty` (fails today). Then re-pair and read it again. `.ambientTestKeyManager`.

---

## KX-5 (Bug 202): a decoded `Contact.Draft` can install keys with no exchange

**Proposed severity: Low, latent.** Not reachable in this build. Filed because it is one line of wiring from breaking the rule that a key is only ever trusted after a physical exchange.

- `Contact.Draft` and `Contact.Draft.Key` are `Codable`, and the key's coding keys include `material` and `quantumKeyMaterial` (`Contact+Draft.swift:389-419`).
- `save(contact:)` for a new contact runs `for key in contact.contactPublicKeys { try? self.update(key: key, for: newContact.identifier) }` (`Contact+Manager.swift:439-441`): whatever keys the draft carries become the contact's keys, at full standing.
- `Import.DisplayImportedContactList` decodes `[Contact.Draft]` from the files of a received basket and passes the selection to `save(contacts:)` (`Import+View.swift:34`, `:187`).

`Import` is only instantiated in its own `#Preview`, so today nothing reaches it, and the two live callers of `save(contact:)` build their drafts locally. If the screen is wired back in, a contact can send a file that creates "Bob" with a key the sender holds.

The draft that `ContactManager` builds for the edit form also carries each key's decrypted ML-KEM secrets (`:1076-1095`); the form does not need them.

### Fix

Remove the loop at `:439-441` (no live caller passes keys), stop decoding `contactPublicKeys` in `Contact.Draft`, and delete `Import+View.swift` or make it drop keys. Leave key material out of the edit form's draft.

### Guard

`ContactTests`: saving a new draft that carries a key leaves the contact with no key row (fails today).

---

## CD-1 (Bug 203): a classical-only exchange skips the card meeting check

**Proposed severity: Medium.** The one detector of a swapped or front-run card does not run, and the contact is marked Verified. Full trace: `agents/hunter-cards.md`, CARDS-1.

`CardMeetingContext.verdict` returns `.none` when there is no hybrid result, even when the contact's card field gives a key to check against (`CardMeetingContext.swift:39-40`). `sendCardProof` is only called from the hybrid assembly (`Exchange+Manager.swift:451`). After the save the card field is wiped (`Contact+Manager.swift:680`) and the screen closes on "Key saved" (`KeyExchange.swift:346-350`). `CardMeetingCheckTests` pins this behaviour ("A classical-only exchange has no transcript: no verdict in any row"), while SPEC §7 says "Otherwise: W-11" and FINDINGS says "The alarm can't be missed".

A card conversation needs iOS 26 at both ends. So when the person met in person has a phone that cannot do ML-KEM, that phone cannot have been the other end of the card conversation, which is exactly the case the warning is for: a card forged in someone's name, or one redeemed by whoever sat in the chat it was sent through. KX-2 reaches the same path from the other side: stripping ML-KEM in transit also switches the check off.

**Fix.** Return `.mismatch` when the context holds a peer signing key and there is no hybrid result. Add the classical row to SPEC §7.

**Guard.** Change `CardMeetingCheckTests.classicalOnly` to expect `.mismatch` for the rows that show a verdict; it fails today. The function is pure, so it runs anywhere.

---

## PK-1 (Bug 204): a prekey batch is accepted without checking that its keys are points

**Proposed severity: Medium.** A contact, or whoever holds a contact's phone, can stop the owner's messages to them for good, and to every group they are in. Full trace: `agents/hunter-challenge-prekeys.md`, HC-1.

`PrekeyBookkeeper.accept` holds each key to 65 bytes and an ID length and nothing else (`PrekeyBookkeeper.swift:121-131`, `:158-161`). The exchange checks the two pair keys with `isP256Point` but not the batch that rides beside them (`PairingOffer.swift:162-181`, `Contact+Manager+Pairing.swift:112-116`). On a send, a prekey that will not load makes `deriveOutboundKey` throw `keyDerivationFailed` (`Crypto+Manager+KeyDerivation.swift:32-40`); nothing falls back. Once the bad one-time keys are used up the bad last-resort key is chosen every time, and it is never removed. A group send seals every member in one call, so one member's bad key fails the whole group.

Not run: that Security.framework refuses the non-point is read from the code, not observed.

**Fix.** `accept` requires every key, the last-resort key included, to load as `P256.KeyAgreement.PublicKey(x963Representation:)`, and throws `malformedBatch` otherwise; `PairingOffer.accepted` does the same for the exchange's batch. On the send side, a prekey whose derivation fails is dropped and the next is tried, ending in the long-term mode, so a record that already holds bad keys recovers.

**Guard.** `PrekeyBookkeeperTests`: a batch with a 65-byte key starting `0x00` throws and leaves the record unchanged (fails today; the suite's `wire()` helper builds keys from random bytes and has to make real points). A send to a contact whose record holds such a batch produces a bundle (`.ambientTestKeyManager`).

---

## PK-2 (Bug 205): a failed send still uses up the contact's one-time key

**Proposed severity: Low.** No secret is exposed; the stock of forward-secret keys for a contact drains without a message leaving. Full trace: `agents/hunter-challenge-prekeys.md`, HC-2.

`encryptBundle` takes the key and writes the shortened record onto the contact (`Contact+Manager.swift:1305-1307`) before `streamedParts`, `seal` and `deliver`, any of which can throw. The save at `:1390` is skipped, but the object keeps the change and the next save commits it. The group path says turning autosave off means "only the explicit save below can persist the pop" (`:1498-1511`); the `defer` turns it back on with the objects still changed. A group with a member that has no current key (a revoked one) throws part-way through and takes a key from every member mapped before it, on every attempt.

**Fix.** Keep the sealed record and put it back in a `catch` on both paths, as `update(key:)` does, or take the key into a local record and write it to the contact only after the bundle is delivered. Correct the comment.

**Guard.** One-to-one: a send whose output cannot be written leaves the inbound key count unchanged. Group: a send that throws on a revoked member leaves the other members' counts unchanged. Both fail today; `.ambientTestKeyManager`.

---

## CD-2 (Bug 206): rejecting an unknown-sender file takes longer when a hidden contact holds an issued card

**Proposed severity: Low.** **Status proposed: open, needs a decision** for what remains after the fix. Full trace: `agents/hunter-cards.md`, CARDS-2.

When no contact matches a file's sender, `redeemCard` runs one Enclave ECDH per forward-secret slot for every contact, at every depth, whose card field is `issued` (`ContactManager+Cards.swift:653-671`). The slot count is bounded only by `Group.slotCount`, 32. A coercer at a duress depth opens two crafted files with unknown senders, one with 32 well-formed slots and one with none: both end in the same alert, and the time between them is 32 Enclave operations per unexpired issued card. Cards on visible contacts can be seen and cancelled; a difference that remains means a hidden contact issued a card in the last 24 hours. The size of the difference on a device was not measured.

SPEC §6.6 accepts the work as work; it does not consider it a depth observable.

**Fix.** Try redemption only for a bundle with exactly one recipient slot, which is what a card bundle has. That cuts the factor from 32 to 1. Removing the rest (a fixed number of Enclave agreements per unknown-sender file, padded with a decoy key) needs a decision.

**Guard.** Inject a `CardKeyProviding` that counts `sharedSecret` calls: with one issued card on a contact hidden at depth 1, a 32-slot unknown-sender bundle opened at depth 1 makes as many calls as with no card. Today 32 against 0. Software keys, runs anywhere.

---

## Known items met again (not re-filed)

| Item | Where recorded | State at this commit |
|---|---|---|
| After a contact's identity key changes on a pairing without pair keys, sends keep using the old phone's prekeys | Bug 194, entry on `claude/bug-194-stale-inbound-prekeys-ee7f61` (PR #156) | Fixed on `release/v2.1.0` only; decided 2026-11-03 not to backport. Present here: `update(key:)` touches the prekey record only `if let pairing` (`Contact+Manager.swift:683`). A pair-key re-pair is not affected (`startPairing` clears the inbound side) |
| Stripping the `pairing` field in both directions gives a plain pairing | Bug 196, decisions table | Accepted, with the confirmation-screen note |
| `rollback()` leaves unsaved values on live objects | Bug 197 | Open; `update(key:)` restores by hand |
| `_peer-data-ex` advertising identifies Occulta to anyone scanning during an exchange | Hardening step 10 | Advertising stops when the screen goes; the service type itself is unchanged |
| Approving an identity challenge answers a contact hidden at the current duress depth | Bug 173 | Open, awaiting a decision since 2026-10-25. Unchanged here, and its guard test (`IdentityChallengeHiddenContactTests`) is not on this branch |
| One phone saves and the other does not, leaving one side refusing the old form | Bug 196, "Residual" | Known; see code-quality note 2 |

## Hardening notes

1. **The classical words are the transport key's output.** `KeyExchange.swift:305` feeds `createSharedSecret(using:)`, the long-term transport key itself, to the word generator. 64 bits of a function of a 256-bit key shown on screen is not a break, but the words should come from their own label. KX-1's fix does this.
2. **The peer's identity key is checked for length only** (`Exchange+Manager.swift:604`). A 65-byte value that is not a point, or the phone's own identity key reflected back, is carried to the confirmation screen; the words then cannot match, but Confirm still saves it when the exchange has no pair keys (`Contact.Draft.Key.init` validates nothing). Refuse both at receipt, as `PairingOffer.accepted` does for pair keys.
3. **`batchDigest` truncates lengths** with `UInt16(truncatingIfNeeded:)` (`PairwiseDerivation.swift:77-86`) while appending the full bytes, so the comment "two different batches never encode alike" does not hold for a field of 65,536 bytes or more. No collision with an honest batch is possible, since an honest batch is far shorter. Bound the batch in `PairingOffer.accepted` before digesting it.
4. **A send silently drops ML-KEM when the stored material will not decode**: `resolveKeyMaterial` uses `try?` (`Contact+Manager.swift:1730-1735`), while the receive side throws `quantumKeyMaterialCorrupted` (`:1771`). A hybrid contact should fail the send, not go classical.
5. **No notice that a contact's identity key changed** on the confirmation screen. `update(key:)` computes `keyRotated` and uses it only for the backup-piece event.
6. `ExchangeManager.log` (`Exchange+Manager.swift:43`) is never used; `debugPrint("Updated existing contact")` at `Contact+Manager.swift:388` is outside `#if DEBUG`.

## Code quality and test coverage

1. **The exchange state machine has no tests.** `handleReceivedData` and `handleNearbyObjectsUpdate` (`Exchange+Manager.swift:525-862`) hold the role choice, the proximity gate, the identity buffer, three backward-compatibility branches and both key paths, in 340 lines of nested closures with five separate 3-second sleeps. The tests cover pinning (2 tests), teardown (4) and the `pairing` field (3 on the manager). Nothing drives an identity or ciphertext message through it, so none of these is pinned: identity ignored before the gate opens, the buffered identity replayed once, a second identity or ciphertext ignored, the classical fallback, the payload both roles assemble. The manager can already be driven without radios (`multipeerSession` is settable); what is missing is a way to open the gate without a real `NINearbyObject`, for example by moving the body of the `for object in nearbyObjects` loop into a method that takes a token and a distance.
2. **No confirmation between the phones before either saves.** Each phone saves on its own Confirm tap. One Confirm and one Cancel leaves one phone with a pair-key pairing that refuses the old form and the other with none. A `confirmed` message each way before the save would shrink this to a lost last message.
3. **The words are a private computed property of a SwiftUI view** (`KeyExchange.swift:285-309`), recomputed on every render with an Enclave ECDH each time, and untested as a whole: which derivation each of the three payload shapes uses is exactly what KX-1 and KX-2 turn on. Move it next to `saveExchange` as a static function and test the three shapes.
4. **`saveExchange` and the screen derive the same keys twice** from the payload (words, then routing key), each with its own Enclave ECDH.
5. Three failure paths in the manager `return` with no state change and no error (`:621` encapsulation failed, `:724` no handle, `:730-735` decapsulation failed). The exchange then sits until the watchdog, and the user sees a generic timeout. `ExchangePhase.failed` exists and is never set.

## Limitation entries for `Docs/Audit/OPEN_LIMITATIONS.md`

That file is gitignored and lives only in the main checkout, so these are listed here for whoever updates it:

- **KX-1 / Bug 198** — open — the verification words do not bind a man in the middle's last message; effective strength about 32 bits until the commit-and-reveal step ships.
- **KX-2 / Bug 199** — open, needs a decision — ML-KEM stripped in transit is not detected by the words and not noted on screen.
- **CD-1 / Bug 203** — open — a classical-only exchange gives no card warning.
- **CD-2 / Bug 206** — open, needs a decision — unknown-sender rejection time depends on issued cards at hidden depths.
- **Bug 194 on 2.0.x** — decided (no backport) — stale inbound prekeys after an identity-key change on a pairing without pair keys.

## Validation plan (Phase 7)

All Simulator-only; none needs a phone.

| Lead | Test that settles it | Gate |
|---|---|---|
| KX-1 | Software-key fixture: fix a victim's nonce, identity and `pairing` field; show that two attacker fields differing only in batch `generatedAt` give different words, with every `wordsKey` input computed from the attacker's side alone | none |
| KX-2 | `saveExchange` with a classical payload over a hybrid pairing is saved today | `.ambientTestKeyManager` |
| KX-3 | Late `.connected` after `finish()` (one-test run, it traps); classical identity then `finish()` then 7 s | none |
| KX-4 | Revoke, read the expired row's pairing state | `.ambientTestKeyManager` |
| KX-5 | Save a new draft with a key, count key rows | `.ambientTestKeyManager` |
| CD-1 | `CardMeetingContext.verdict` with a peer signing key and no hybrid result returns `.none` today | none (pure function) |
| PK-1 | `accept` takes a batch whose key is 65 bytes starting `0x00`; then a send to that contact throws | none; then `.ambientTestKeyManager` |
| PK-2 | Inbound key count after a send that throws | `.ambientTestKeyManager` |
| CD-2 | Count of `sharedSecret` calls for a 32-slot unknown-sender bundle, with and without a hidden issued card | none (software keys) |

The pin race in KX-1 and the size of the timing difference in CD-2 are the two facts a Simulator cannot give. Both need hardware, and neither changes whether the finding holds, only how often or how visibly.

## Coverage

One unit is a surface, a boundary and an attack class. `covered` means every starting path was read in full by the reader named.

| Unit | Surface → boundary | Class | Status | Reader | Result |
|---|---|---|---|---|---|
| E3a | `Exchange+Manager.swift` messages → peer pinning, proximity gate | Peer identity confusion; stale and out-of-order messages | covered | parent, then verifier | KX-1, KX-3 |
| E3b | Verification words (`KeyExchange.swift`, `PairwiseDerivation.swift`, `Key+Manager.swift:1663-1921`, `Passphrase+Manager.swift`) → what the words bind | Cryptography; downgrade | covered | parent, then verifier | KX-1, KX-2 |
| D1x | Exchange derivations: routing key, long-term slot key, hybrid transport key, words key | Key derivations with public inputs | covered | parent | none; hardening 1 |
| P1 | `PairingOffer`, `PairingCodec`, `PairingState`, `PairingSlotKeys`, `Contact+Manager+Pairing.swift` → acceptance of the peer's field, sealed column | Business logic; bounds | covered | parent | hardening 3; PK-1 (batch) |
| U1 | `update(key:for:pairing:)`, `reset(identity:)`, `saveExchange` → rollback, retirement | Half-saved state; stale keys after retirement | covered | parent | KX-4; Bug 194 (known) |
| U2 | `save(contact:)`, `Import+View.swift` → keys only from an exchange | Import authority | covered | parent | KX-5 |
| PQ | `PostQuantumProvider.swift`, `QuantumKeyMaterial.swift`, `CardKeys.swift` → Enclave binding of exchange keys | Cryptography | covered | parent | none |
| B1, B4, B5 | Card import, redemption, card-holder resolution | Business logic; envelope identity | covered | hunter (cards) | CD-2; notes |
| E3c | Card meeting check (`CardMeeting.swift`, `CardMeetingContext.swift`) | Stale acceptance; downgrade | covered | hunter (cards) | CD-1 |
| B2 | Card lifecycle: sweep, cancel, deletion | Stale authorization | partly | hunter (cards) | notes; migration and Erase All Data not read |
| C5 | Identity challenge: coordinator, manager, envelope, ledger | Reply correlation; peer identity | covered | hunter (challenge) | none new; Bug 173 (known, open) |
| C4 | Prekey record, bookkeeper, secrets manager, first batch | Consumption order; replay | covered | hunter (challenge) | PK-1, PK-2 |
| A-KE | Exchange and confirmation screens at a duress depth | Depth observables | partly | parent | none seen; screens are reached per visible contact only. Not traced: contact detail's revoke and capability rows |
| D3-KE | Traces the ceremony leaves: logs, UserDefaults, keychain, temp files | Forensic traces | covered | parent | none new: Enclave keys have no keychain item, logging is `#if DEBUG`, one stray `debugPrint` (hardening 6) |
| C1-KE | `Exchange` JSON decoding of peer bytes | Crash before authentication | covered | parent | none: `Codable` decode, secure unarchive of the token by class, sizes checked before use |
| G1 | Group encrypt and decrypt beyond prekey use | — | deferred | — | out of this audit's scope |
| M1 | `PQmigration.swift`, `KeyReseal*` handling of key rows and prekey records | Migration | deferred | — | belongs to the local-keys audit |
| T1 | Tier negotiation (`resolveTargetVersion`, `updateMaxVersion`) | Downgrade by a contact | deferred | — | not reached |

## Deviations and what was not covered

- **Run status: incomplete.** Three units are deferred and two are partly covered (table above), and no coverage critic ran.
- **Fewer agents than the skill plans.** No recon agents: the parent read the area itself. Two hunters (cards; identity challenge and prekeys) and one verifier, against the skill's 5 recon, one hunter per 1–3 units and a critic. The parent hunted the ceremony, pairing and save units directly.
- **The skill's prompt assembly, ledger scripts and validators were not used.** Hunters and the verifier were briefed in plain text with the threat model file, and wrote Markdown. `coverage-ledger.json` and `findings.json` in this folder are hand-written in a simple shape and have not been through `validate-coverage-ledger.cjs` or `validate-findings.cjs`.
- **Independence of verification.** KX-1, KX-2 and KX-3 were hunted by the parent and checked by a separate verifier that was asked to refute them; it confirmed all three and corrected two details (the cheaper nonce route, and the pin race as a precondition). CD-1, CD-2, PK-1 and PK-2 were hunted by subagents and re-read by the parent against the cited lines. KX-4 and KX-5 were hunted and checked by the parent only: nobody else has tried to refute them.
- **Models.** The session began on Sonnet 5.5 and continued on Fable 5.2. Hunters ran on the session's model, the verifier on Sonnet. All three agents hit the usage limit once and were resumed.
- **Nothing was executed.** No build, no test, no Simulator, no phone. No production code was changed and nothing was committed.
- **Not measured:** how often an attacker wins the Multipeer pin on both phones (KX-1), per-operation Enclave time (CD-2), and whether Security.framework refuses a non-point as read (PK-1).

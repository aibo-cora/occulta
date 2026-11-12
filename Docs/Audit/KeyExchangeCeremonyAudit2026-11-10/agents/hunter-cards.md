# h-cards — introduction-card flows (commit 87d9bf11)

Read-only source review. Nothing was built or run, so every candidate below is unreproduced and needs a test before it is filed.

## 1. Coverage

**Read fully**

| File | Lines |
|---|---|
| `Occulta/Features/IntroductionCards/ContactManager+Cards.swift` | 1–757 |
| `Occulta/Features/IntroductionCards/Crypto+Manager+Cards.swift` | 1–460 |
| `Occulta/Features/IntroductionCards/CardKeys.swift` | 1–112 |
| `Occulta/Features/IntroductionCards/CardRules.swift` | 1–127 |
| `Occulta/Features/IntroductionCards/CardState.swift` | 1–57 |
| `Occulta/Features/IntroductionCards/CardStateCodec.swift` | 1–63 |
| `Occulta/Features/IntroductionCards/CardMeetingContext.swift` | 1–51 |
| `OccultaCore/Sources/OccultaFormats/IntroductionCard.swift` | 1–191 |
| `OccultaCore/Sources/OccultaFormats/CardIntroduction.swift` | 1–71 |
| `OccultaCore/Sources/OccultaFormats/CardBootstrap.swift` | 1–135 |
| `OccultaCore/Sources/OccultaFormats/CardMeeting.swift` | 1–72 |
| `OccultaCore/Sources/OccultaFormats/MLKEMKeyCheck.swift` | all |
| `Occulta/UI/Tabs/Contacts/IntroductionCards/CardImportSheet.swift` | 1–257 |
| `Occulta/UI/Tabs/Contacts/IntroductionCards/ContactCardSection.swift` | 1–320 |
| `Occulta/UI/Tabs/Contacts/IntroductionCards/CardFirstMessageFrame.swift` | 1–67 |
| `Docs/Features/Introduction Cards/SPEC.md` | 1–446 |

**Read partially**

| File | Lines |
|---|---|
| `Occulta/Services/Contact+Manager.swift` | 471–492, 560–760 (`update(key:)`), 1196–1275 (`sendBundle`), 1757–1775, 1820–1970 (`identifyOwner`, `cardHolder`), 2050–2070, 2180–2460 (`openGroup`) |
| `Occulta/App/OccultaApp.swift` | 425–500, 535–560, 790–935 (`processInboundFile` and its error mapping), 950–1260, 1370–1410 |
| `Occulta/UI/Tabs/Contacts/Key+Exchange/KeyExchange.swift` | 14–400 |
| `Occulta/Services/Exchange+Manager.swift` | 1–15 (grep), 205–235, 340–395, 440–465, 480–690 |
| `Occulta/UI/Tabs/Contacts/IntroductionCards/CardMeetingVerdictView.swift` | 1–70 |
| `Occulta/UI/Tabs/Contacts/IntroductionCards/IntroCardCopy.swift` | 139–147, 182, 244–300 (grep only) |
| `Occulta/UI/Tabs/Contacts/v2/ContactDetailV2.swift` | 40–299 |
| `Occulta/UI/Tabs/Contacts/v2/Contacts+DesignTokens.swift` | 50–140 |
| `Occulta/UI/Tabs/Contacts/v1/Contact+Detail.swift` | 1–90 |
| `Occulta/Services/BundleBody.swift` | 40–165 |
| `Occulta/Services/Key+Manager.swift` | 1740–1830 (`forwardSecretSessionKey`) |
| `Occulta/Services/Contact+Manager+Pairing.swift` | 88–92 |
| `Occulta/Services/ReceivedAttachmentKey.swift` | 13–55 |
| `Occulta/Features/ShareExtension/ShareSession.swift` | 215–245 |
| `Occulta/UI/Tabs/Contacts/v2/ContactsListV2.swift` | 285–310 |
| `Docs/Features/Introduction Cards/FINDINGS.md` | 1–80, 199–213, 251–265, 289–420, 499–510 |
| `Docs/Features/Secure Mode/bugs.md` | Bug 160–197 headings; Bug 163, 164, 182 excerpts |
| `Docs/Bugs/v1.10.0/Non-Safe-Sender-Rejection-Is-A-Duress-Detection-Oracle.md` | 549–632 |
| `OccultaTests/IntroductionCards/` | file listing; `CardMeetingCheckTests.swift` 255–285; test-name greps |

**Not read:** `IntroCardComponents.swift`, `BUILD_PLAN.md`, the rest of `IntroCardCopy.swift`, `Contact+Manager+Groups.swift`, `PQmigration.swift`, the card migration (`migrateCardFields`).

## 2. Candidates

### CARDS-1 — A classical-only in-person exchange shows no W-11, so an intercepted or forged card conversation ends as Verified with no warning

**Proposed severity:** medium. The design's one detector of a swapped or front-run card is silently skipped. The impersonation before the meeting is an accepted limit; the missed alarm is not.

**Evidence**
- `Occulta/Features/IntroductionCards/CardMeetingContext.swift:39-40`: `guard let key = context.peerSigningKey, let result, let ourIdentity else { return .none }`. A nil `result` (no `HybridExchangeResult`) gives `.none` even when `peerSigningKey` is set, i.e. when the field is `conversation` or `imported` with a message sent.
- `Occulta/Services/Exchange+Manager.swift:650-690`: the exchange is classical-only whenever the peer's identity message has no `encapsulationKey` (a phone on iOS 18.6–25, or no provider or private key). `hybridResult: nil`.
- `Occulta/Services/Exchange+Manager.swift:451`: `sendCardProof` is only called on the hybrid path, so a classical exchange carries no proof either way.
- `Occulta/UI/Tabs/Contacts/Key+Exchange/KeyExchange.swift:339-350`: after `.saved`, `verdict == .none` closes the screen after one second with "Key saved".
- `Occulta/Services/Contact+Manager.swift:680`: the same save runs `clearCard(afterMeetingOf:)`, which wipes the card field. Nothing about the verdict is stored (Q-10), so nothing remains afterwards.
- `OccultaTests/IntroductionCards/CardMeetingCheckTests.swift:264-272` pins this: "A classical-only exchange has no transcript: no verdict in any row".
- It contradicts `SPEC.md` §7 ("Otherwise: W-11. That covers a filler, a bad signature, or no proof message from an older build") and `FINDINGS.md:251` ("The alarm can't be missed"). SPEC §7 has no classical-only row.

**Attack trace**
1. Attacker M controls the chat a card travels through (the threat W-02 and W-05 describe).
2. Variant A (forged card): Bob's phone runs iOS 18.6–25, which is inside the deployment target and cannot create cards. M sends Carol (iOS 26) a card M made, "from Bob". Carol imports it and writes; her field is `imported` with `sentFirstMessage == true`, then `conversation` once M replies. M reads everything.
3. Variant B (front-run): Bob (iOS 26) issues a card for Carol, whose phone is on iOS 18.6–25 and cannot import it. M redeems it first (`redeemCard`, `ContactManager+Cards.swift:647`). Bob's field is `conversation` with M's keys.
4. The two real people meet and run the exchange from the contact's details. The older phone sends no `encapsulationKey`, so the exchange is classical and `payload.hybridResult == nil`.
5. `cardMeetingVerdict` returns `.none`. The iOS 26 phone shows "Key saved", the contact becomes Verified, and the card keys are wiped. No W-11 is shown.

**Why existing guards don't stop it.** The verdict needs a transcript, which is built from ML-KEM ciphertexts. With no hybrid result the code treats "can't check" as "nothing to show". But a card conversation requires iOS 26 at both ends (SPEC §1), so a peer that cannot do ML-KEM cannot have been the other end. The confirmation screen only omits its "Quantum-resistant exchange" label, which a user has no reason to read as a card warning.

**Not verified:** whether a nearby radio peer can strip `encapsulationKey` from both identity messages to force this path. The `MCSession` uses `encryptionPreference: .required` (`Exchange+Manager.swift:182`). That belongs to the ceremony hunter.

**Confidence:** high on the code path; medium on severity, since it needs one phone below iOS 26.

**Fix.** In `CardMeetingContext.verdict`, return `.mismatch` when `context.peerSigningKey != nil` and `result == nil`. `.none` stays for `ourIdentity == nil` only if that case is unreachable after a save. Add the classical-only row to SPEC §7.

**Test plan.** Change `CardMeetingCheckTests.classicalOnly` to expect `.mismatch` for the rows that show a verdict (`conversation`; `imported` after a send) and `.none` for the rest. It fails today. Add a `KeyExchange.saveExchange`-level test that a `conversation` contact saved from a payload with `hybridResult == nil` yields `.mismatch`. The verdict function is pure, so a hand-built `CardMeetingContext` runs on the Simulator and on CI; the existing `CardPhonePair` rows are Enclave-gated.

### CARDS-2 — The time to reject an unknown-sender bundle grows with the number of unexpired issued cards at every depth, hidden ones included

**Proposed severity:** low. It is a depth observable with a narrow window: a hidden contact must hold an `issued` card less than 24 hours old.

**Evidence**
- `Occulta/Services/Contact+Manager.swift:1898`: when no contact matches, `identifyOwner` calls `redeemCard`.
- `Occulta/Features/IntroductionCards/ContactManager+Cards.swift:653-671`: for every contact at every depth whose field is `issued`, and for every `.forwardSecret` slot with a 65-byte ephemeral key, it calls `self.cardKeys.sharedSecret(agreementBlob:peerPublicKey:)`.
- `Occulta/Features/IntroductionCards/CardKeys.swift:74-78`: in production that is a Secure Enclave key load plus an Enclave ECDH.
- `ContactManager+Cards.swift:648-649` bounds slots only by `Group.slotCount`, which is 32 (`Occulta/Data Models/Group+Model.swift:57`). A real card bundle has exactly one slot (`sendCardBundle`, `ContactManager+Cards.swift:482`).

**Attack trace**
1. A coercer at a duress depth crafts two v4 group bundles with a random sender fingerprint. Bundle X has 32 `.forwardSecret` slots, each with a valid P-256 point as its ephemeral key and junk `wrappedPayload`. Bundle Y has 32 slots whose ephemeral keys are not 65 bytes.
2. They open each in Occulta. Both end in the same alert (`noPublicKeyToEncryptWith`).
3. Y costs no Enclave work. X costs 32 Enclave ECDH operations per unexpired `issued` card on the phone.
4. Issued cards on visible contacts can be seen in the UI, and cancelled. A remaining gap between X and Y means a hidden contact holds an active card, so a hidden depth exists and was used in the last day.

**Why existing guards don't stop it.** SPEC §6.6 accepts the cost as work ("Someone holding a card can make Bob's phone do that work, and nothing more") but does not treat it as a depth observable. The accepted own-card refusal (`FINDINGS.md`, decided 2026-10-19) needs the hidden card's file; this needs no file.

**Not measured:** the per-operation Enclave time on a device, so the size of the gap is an estimate (I assumed roughly 10 ms per operation, a few tenths of a second per card at 32 slots). The call count is certain.

**Confidence:** medium.

**Fix.** Attempt redemption only when the bundle has exactly one recipient slot. That cuts the multiplier from 32 to 1. To remove the residual, do a fixed number of Enclave agreements per unknown-sender bundle, padding with a decoy key. This one needs a decision on whether the residual matters.

**Test plan.** Inject a `CardKeyProviding` that counts `sharedSecret` calls. With one `issued` card on a contact hidden at depth 1, open a 32-slot unknown-sender bundle at depth 1 and assert the count equals the count with no issued card. Today it is 32 against 0. Software keys, so it runs on the Simulator and on CI.

## 3. Hardening notes

- **Known, open: inbound error text separates a matched card holder from an unknown sender.** A bundle whose fingerprint is `SHA-256(card agreement key ‖ nonce)` built from a card file gives "This message couldn't be opened" when any contact at any depth holds that card, and the unknown-sender alert otherwise (`OccultaApp.swift:853-931`). This is Case B, probe 3, in the Non-Safe-Sender doc (lines 594–632), status "open, needs a decision". Not re-reported.
- **Known class: Carol's bootstrap messages are re-openable on Bob's phone until the meeting.** They are sealed to his static card key under a random `prekeyID`, so nothing is consumed (`Crypto+Manager+Cards.swift:359-365`). Anyone with a copy can replay them, and they open at a duress depth. This is Case A of the same doc (open). The card-specific point it doesn't state: it covers every message Carol sends before Bob's reply reaches her, not one in sixteen.
- **The introduction doesn't prove possession of its agreement key.** `CardIntroduction.verify` checks a signature by the signing key only, and the fingerprint and `senderProof` checks in `redeemSlot` need only the public key (`ContactManager+Cards.swift:725-745`). A redeemer can name any public key, such as another contact's card agreement key. The effect I could trace is limited to routing confusion: two holders of one peer key, with `cardHolder` falling back to `holders[0]` for a slot that names no held prekey (`Contact+Manager.swift:1909-1916`), which can make a long-term or last-resort slot fail on the wrong contact. An ECDH-derived check at redemption, or resolving `cardHolder` by trial, would close it.
- **`createCard` and `importCard` gate on `hasInPersonKeys`, not on "holds a current key".** A contact whose current key has another owner hash (status `.unverified`) passes the manager's check (`ContactManager+Cards.swift:124, 301`), and `sendBundle` would then switch it to card keys (`Contact+Manager.swift:1239`). The UI offers neither action for such a contact, so this is unreachable today.
- **Replacing a waiting card needs no extra confirmation.** Import into an `imported` contact with `sentFirstMessage == true` overwrites the keys Bob's pending reply needs (`CardRules.swift:67-68`, decided in SPEC §6.3). Any self-signed card the user attaches to that contact does it; the sheet shows the same warning as a first import.
- **W-11 lives in view state only.** The key is saved before the verdict screen is shown (`KeyExchange.swift:334-353`). If the process dies between the two, the contact is Verified, the card is wiped and the warning is gone. Decided as "store nothing" (Q-10); the window is small.
- **Redemption commits before the ordinary open.** `redeemCard` saves `conversation` and drops the card's ML-KEM key (`ContactManager+Cards.swift:679-694`) before `openGroup` runs. `redeemSlot` repeats most checks but not `body.authenticateHeader` (the Bug 181 check, `Crypto+Manager+Cards.swift:316`). Only a card holder can reach this, and a card holder can redeem anyway, so it is consistency, not an attack.
- **An expired card's cancel failing changes the error.** `redeemCard` uses `try self.cancelCard` inside the loop (`ContactManager+Cards.swift:657`), so a failed save surfaces as a generic error and not as an unknown sender.
- **The sweep can leave a pending batch.** `sweepCards` reads the record with `try?` (`ContactManager+Cards.swift:367`); an unreadable record keeps its pending Enclave prekeys while the card is cleared.
- **Doc and code disagree** on SPEC §7's "Otherwise: W-11" against `CardMeetingContext`'s comment and the pinned test (see CARDS-1).

Checked and found sound: card recognition (length, on-curve parse, modulus check, signature; no trap on any input); `CardStateCodec.decode` bounds; `CardBootstrap` length checks; no classical or identity-key downgrade for a card contact (`quantumMaterialMissing` throws, NoPQ modes are unusable slots); reflection of a long-term slot (stopped by `senderProof` over the sender's key); meeting-proof reflection and cross-meeting replay; shard, custody and identity-challenge content from a card sender (stripped or refused in `openGroup`); card import state across `endSession` (`cardImport` and `contactOpenRequest` cleared, `OccultaApp.swift:576-577`); far-future card expiry (clamped by `recipientDeadline`).

## 4. Test coverage gaps

- No test expects a verdict for a classical-only exchange with a card conversation; the existing test pins `.none` (CARDS-1).
- No test bounds the Enclave work, or the slot count, of `redeemCard` for an unknown-sender bundle (CARDS-2).
- No test for two holders of one peer card key where the bundle's slot is long-term or last-resort (`cardHolder`'s `holders[0]` fallback). `CardConversationTests:491` covers the prekey-named case only.
- No test for an introduction whose `agreementKey` is a key the redeemer doesn't hold, or equals another contact's key.
- No test that the inbound alert is the same for a matched card holder whose slot fails and for an unknown sender (the Case B test plan, not yet written).
- No test for `importCard` or `createCard` on a contact holding a current key with a foreign owner hash.
- No test for `redeemCard` when `cancelCard` throws, or for `sweepCards` with an unreadable prekey record.
- No test for replacing an `imported` card after a first send and then receiving Bob's reply to the old one.

## 5. Not reached

- `IntroCardComponents.swift`, most of `IntroCardCopy.swift`, `BUILD_PLAN.md`, `Contact+Manager+Groups.swift` (group refusal of card contacts), `migrateCardFields`.
- The compose path's secrecy label for card contacts (`ComposeHeroV2`, `cardSecrecyIsStandard`) against SPEC §4.3.
- Whether Erase All Data, depth purges and contact deletion cover every copy of the card field beyond `deleteContact` writing `.empty` (`Contact+Manager.swift:548`).
- The share-extension staging of a card file beyond `ShareSession.introductionCard`.
- Whether the "Not verified" list footer and section in `ContactsListV2` are computed from depth-filtered contacts only.
- The card field's sealed size on a device, and `CardStateCodec.capacity` against real Enclave blob sizes.

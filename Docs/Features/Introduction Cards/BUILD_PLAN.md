# Introduction Cards — Build plan, phase 2 (wiring)

**Status:** Draft for review, 2026-10-17. Phase 1 (standalone pieces) is done: `b82d704`, `52ce4df`, 160 tests passing.
**Design:** [SPEC.md](SPEC.md) (formats and procedures), [FINDINGS.md](FINDINGS.md) (decisions and copy).

Phase 2 wires the phase-1 pieces into storage, sending, receiving, the in-person exchange and the screens. Each
stage leaves the app shippable: until stage E puts card UI on screen, nothing a user can reach changes.

**Agents:**
- **Logic:** stages A–D.
- **UI:** stage E, which starts once stage A has merged and runs alongside C and D.
- **Testing:** follows each stage.
- **Orchestrator:** reviews every diff against the SPEC, runs the tests independently, and commits.

---

## Stage A · The card field (storage only)

**Goal:** every contact carries a fixed-size, sealed card field, never nil. Nothing reads it yet.

| File | Change |
|---|---|
| `Data Models/Contact+Model.swift` | `var introductionCardEncrypted: Data?` on `Contact.Profile` |
| `Features/IntroductionCards/ContactManager+Cards.swift` (new) | `loadCardState(for:)` / `store(_:for:)`: `CardStateCodec` plus the local DB key (`Manager.Crypto`). An unreadable or missing field reads as `.empty` |
| `Services/Contact+Manager.swift` | Write the sealed `.empty` state when a contact is created (`save(contact:)`, `createContacts(from:)`), and overwrite it with `.empty` on soft and hard delete |
| `Features/PostQuantum/PQmigration.swift` | `DatabaseMigration.migrateCardFields`: writes sealed `.empty` to every row where the field is nil |
| `App/OccultaApp.swift` | Call the migration next to `migratePrekeyRecords`, at launch and at unlock |

**Tests:**
- A created contact has the field, at the fixed sealed length.
- The migration fills every nil row, is idempotent, and changes no other field.
- Deleting a contact overwrites the field with `.empty` at the same length.
- An unreadable field reads as `.empty`.
- These use `.ambientTestKeyManager`.

**Migration:**
- **Schema:** a SwiftData lightweight migration adding one optional attribute.
- **Rows:** a launch pass fills every row with the sealed empty state, as `migratePrekeyRecords` did, so a NULL can't separate contacts.
- **Failure:** if the pass fails, the field stays nil, reads as `.empty`, and the pass retries at the next launch or unlock.
- **Existing data:** no existing field is touched.
- **Downgrade:** an App Store build can't be downgraded.

---

## Stage B · Issuing, importing and expiry (no messages yet)

**Goal:** Bob can create, share and cancel a card. Carol's phone can recognise it and import it. The unlock sweep clears dead cards. No message is sent or received through a card yet.

| File | Change |
|---|---|
| `Features/IntroductionCards/CardKeys.swift` (new) | A `CardKeyGenerating` protocol: an Enclave agreement key and signing key, saved as blobs. Implementations: Enclave, and software for tests. ML-KEM goes through `PostQuantumProvider.generatePersistentKeyPair` |
| `Features/IntroductionCards/ContactManager+Cards.swift` | `createCard(for:)`: generate keys, sign, store `issued`. `cancelCard(for:)`. `importCard(_:into:)`: recognise, collect the agreement keys of the user's own issued cards across every contact and depth, apply `CardRules.importDecision`, and run the matching step (import, replace, cancel own and import, or refuse). Carol's import generates her keys and her own prekey batch (through the existing `PrekeySecretsManager` / `PrekeyRecord` path), encapsulates to get `ss1` and `ct1`, and stores `imported`. `sweepCards()` applies `CardRules.sweep` to every contact at every depth |
| `App/OccultaApp.swift` | Route an inbound file that `IntroductionCard.recognize` accepts to the import flow, **before** the bundle decoder. Call `sweepCards()` next to `sweepPrekeysIfUnlocked` |
| `ShareExtension/ShareViewController.swift` | Hand a recognised card file to the app the way staged files are handed over today. The activation rule already accepts files of any type |

**Tests:**
- Create, then recognise the shared bytes, then import on a second, simulated phone. Check the state on both.
- Cancel deletes the keys.
- Every import decision runs end to end, including key order with two simulated phones and own-card refusal across depths.
- The sweep runs at every depth and keeps the field at the same length.
- Recognition is tried before bundle decoding.
- Key creation needs a real Enclave and is gated. Everything else injects software keys.

**Migration:** none. This stage uses stage A's field.

---

## Stage C · Messages in a card conversation

**Goal:** Carol can write to Bob and Bob can reply. This covers the bootstrap layer, redemption, both ML-KEM secrets, and the move to ordinary forward-secret slots.

**Most likely to conflict with other work.** `Contact+Manager.swift` and the group crypto files change often. Check open branches and merge `release/v2.0.0` before starting.

| File | Change |
|---|---|
| `OccultaFormats/OccultaBundle.swift` | `RecipientPayload.introduction: CardIntroduction?`, decoded with `decodeIfPresent` |
| `Forward+Secrecy/Crypto+Manager+GroupEncrypt.swift` | `wrapRecipient` takes the sender's key choice. For a card contact, `senderEphemeralSignature` is signed with the card signing key. The bootstrap layer is applied when the card state says so |
| `Forward+Secrecy/Crypto+Manager+GroupDecrypt.swift` | Opening a bootstrap slot: ordinary key first, then the bootstrap layer (§4.3). The redemption trial: one ECDH per active card per slot |
| `Services/Contact+Manager.swift` | **Send:** `encryptGroupBundle` uses the card agreement key for the fingerprint, `senderProof` and long-term ECDH. Carol's slots are ephemeral-to-static to Bob's card key with a random `prekeyID` (§6.5). `sentFirstMessage` is saved before the bundle is handed off. `CardRules.canSend` is enforced. **Receive:** `identifyOwner` also matches peer card keys from `imported` and `conversation` fields; with no match it tries redemption (§6.6); then come Carol's `ss2`, clearing Bob's `bootstrapOpen`, the duplicate-introduction check, and the expiry check at every depth |
| `Features/IntroductionCards/ContactManager+Cards.swift` | The state transitions above. Bob's first batch is made at redemption, once every check has passed |
| `UI/Tabs/Contacts/v2/ComposeViewModel.swift` | The secrecy label: Standard Encryption for Carol's slots sealed to Bob's card key (§4.3) |

**Tests:**
- **A two-phone simulation, like `PrekeyConversationSimulationTests`:**
  1. Bob issues, Carol imports.
  2. Carol's messages 1 and 2 arrive in the order 2, 1. Both open, and 2 redeems.
  3. Bob replies, Carol opens it, and both leave bootstrap.
  4. Later messages are ordinary forward-secret slots.
- **Rejected:**
  - a second sender with a different introduction;
  - redemption after expiry;
  - a message from any other sender on a card contact.
- **Duress:** a hidden-depth card is redeemed at a duress depth.
- **Labels:** Standard Encryption until Carol holds Bob's batch.
- **No silent degradation:** a card contact never gets an identity-key bundle.
- **Vector:** a new `recipientPayload.introduction` interop vector, and every existing vector unchanged.

**Migration:** none.
- **Wire:** the new payload field is optional and ignored by builds that don't know it.
- **Compatibility:** only builds that support cards can be card contacts.

---

## Stage D · The meeting check

**Goal:** an in-person exchange with a card contact checks the earlier conversation and shows W-12 or W-11, then clears the card.

| File | Change |
|---|---|
| `Data Models/Exchange.swift` | An optional `cardProof: Data?` field, and `isCardProof`, checked **before** `isDiscovery` |
| `Services/Exchange+Manager.swift` | Once the ML-KEM step completes, compute `CardMeeting.transcript` from `HybridExchangeResult` and send a proof message: a real proof whenever the card field holds this side's card signing key (`issued`, `imported`, `conversation`), otherwise `CardMeeting.filler()`. Receive and keep the peer's proof. Which side shows a verdict, and how each state is cleared, follows SPEC §7's table |
| `UI/Tabs/Contacts/Key+Exchange/KeyExchange.swift` | After the ceremony's own confirmation, show the verdict. W-12, or W-11 with an explicit acknowledgment that can't be swiped away. A ceremony that fails gives no verdict |
| `Services/Contact+Manager.swift` / `ContactManager+Cards.swift` | Saving the exchange (`update(key:for:)`): the contact takes the identity keys and material, the card field is written `.empty`, and the card batches are dropped from the record. Nothing about the verdict is stored |

**Compatibility, checked 2026-10-17.** An older build reads the proof message as a discovery message: no identity and no ciphertext, and JSON ignores the unknown key. Its empty token fails to unarchive, so the message is dropped harmlessly. A test pins this.

**Tests:**
- Proof match gives W-12. A filler, a bad signature, or no proof message gives W-11.
- Every row of SPEC §7's table. In particular, Carol `imported` with a message sent, meeting Bob in `conversation`, gets W-12 on both phones, not a false W-11. `issued` and unsent `imported` show nothing and are cleared.
- The proof message is the same length either way.
- An older decoder drops it harmlessly.
- After the exchange the card field is `.empty`.
- No verdict is stored.

**Migration:** none.

---

## Stage E · Screens (UI agent; starts after stage A, alongside C and D)

| Step | Files | Change |
|---|---|---|
| E1 · Tier | `Contacts+DesignTokens.swift`, `ContactsListV2.swift`, `ContactDetailV2.swift`, `ShareRecipientPicker.swift`, `ContactClassification.swift` | `.unverified` becomes Not verified, computed with `CardRules.tier` from the card field (Q-14). The "UNVERIFIED" label goes away. `UnverifiedNoticeV2` is replaced by W-06's trust line |
| E2 · Hard blocks | `Group+FormV3.swift` (group eligibility), `Vault+ShardSetup.swift` | Card contacts are excluded explicitly with `CardRules.isHardBlocked`, and the row shows W-10. Groups need the explicit check: card contacts can reach a group-capable `maxBundleVersion` from received messages |
| E3 · Contact details | `ContactDetailV2.swift` | The card section (§3's grouping rule): pending (create, active card with countdown, share, cancel), imported (trust line, deadline), conversation (trust line, "Wasn't {Name}?" and discard). Create is disabled below iOS 26 |
| E4 · List and import | `ContactsListV2.swift`, `OccultaApp.swift` | The live list lines. The import sheet with "Import and write to {Name}", and the W-16, W-17 and W-18 refusals |
| E5 · Messages | Read view, compose | "Reply to {Name}" on the first message (W-08). The compose secrecy label |
| E6 · Clean-up | `UI/Mocks/IntroductionCards/`, `OccultaApp.swift`, `AppDelegate.swift` | Delete the mocks and both `-IntroCardMocks` hooks |

**Tests:**
- Tier mapping and eligibility filters exclude card contacts.
- Each screen's view state comes only from the card state and never from depth.

**Migration:** none. The tier is computed, never stored.

---

## Stage F · Release readiness

- **README:** reword "No one can impersonate you remotely" in the same release (Q-01).
- **Full suite** on a host with an Enclave: exactly the six `KeychainMigrationSETests` skips.
- **On a device with no real data:**
  - the card field size test;
  - a hostile ML-KEM blob passed to the Enclave reload;
  - the end-to-end flow on two phones.
- **Docs:**
  - `FORWARD_SECRECY_GUIDE.md`: card conversations;
  - `SECURITY_CHECKLIST.md`: a cards entry;
  - FINDINGS' action items.

## Order

```
A ──► B ──► C ──► D ──► F
└──────► E1, E2 ──► E3, E4 (after B) ──► E5 (after C) ──► E6 (after D)
```

## Decisions needed before starting

None blocking. One thing to confirm, and one fact checked:
1. **V3 detail view: checked.** `ContactDetailV3` is never constructed, and navigation goes to `Contact.DetailsV2`. Stage E wires V2 only.
2. **Stage C timing.** It touches the files other active work changes most. Proposal: run stages A and B now, then check open branches before C.

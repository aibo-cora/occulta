# Introduction Cards — Design Findings

**Status:** Proposal. SPEC drafted 2026-10-16 ([SPEC.md](SPEC.md)); it pins down the formats and procedures and wins where it is more specific than this document. D1 is decided: the carrier route is allowed (Q-01). D2 is decided: send-capable (Q-02). Not scoped for a release.
**Origin:** Design discussion, 2026-10-14. The question raised was whether a contact's *encryption* key could be vouched for, rather than their identity key, so that people we introduce can encrypt to them, marked unverified until they meet. It was assessed against the no-vouching rulings, Sweep 4's trust ladder and the shipped receive path, then reshaped into owner-issued, single-use cards.
**Relation to earlier plans:** this is a worked design for Sweep 4 components 1 and 4 (`Friction/USER_ENGAGEMENT_FRICTION.md:284`). It replaces component 1's card and recasts component 4, so the mutual contact carries a card and asserts nothing. Every earlier plan it touches is listed in [Relationship to earlier plans](#relationship-to-earlier-plans), and each one points back here.
**Decided so far (2026-10-14):** the carrier is never named on the recipient's phone (Q-07). A card may reach its recipient directly or through any number of carriers, and the issuer chooses a named or an open card when creating it (§4). Two ways of recording the route were considered and not adopted ([Considered and not adopted](#considered-and-not-adopted)).
**Decided 2026-10-15:** card contacts and shared/transferred keys share one Not verified tier, and the card warning rules apply to both (Q-14). No imported keys exist, so in practice the tier holds only card contacts. The carrier route is allowed, because it grants no trust (Q-01). A card contact can send before meeting (Q-02). **v1 is direct only.** A card is created from a pending contact's details. Each contact has at most one active card, stored on the contact, with no limit across the app. Cards expire after 1 day. Only the active card is listed (Q-05). At the meeting, the exchange runs from the contact's details and checks the earlier conversation (§3–§5, Q-10). Carriers of any length and open cards are deferred until direct cards ship (§4). One "Not verified" badge for every route, with no route text and no stored route kind (Q-07). For a Not verified contact the secrecy indicator drops its green and the trust line sits above it (Q-09).
**Decided 2026-10-16:** the card carries no prekeys. Carol's first messages are sealed to Bob's card agreement key, and prekeys start flowing in the conversation, as they do between contacts who met in person ([SPEC.md](SPEC.md) §1). This removed the prekey-ID linkage. Messages before prekeys flow are labelled Standard Encryption.

Names used below: **Bob** issues a card. **Carol** receives it and has never met Bob. **Alice** is a verified contact of Bob's who may carry the card. **Dave** is a later carrier whom Bob may not know.

---

## The proposal, as raised

> What if we vouch for an encryption key? We could share our contacts' encryption key, like public keys being shared freely today, so that other people can encrypt messages to us. They would be marked as anonymous because it came from an unknown to us personally contact. To become trusted, users still need to go through the key exchange ceremony we have today.

---

## Assessment

### D-01 · There is no separate encryption key to vouch for

The long-term P-256 key does both jobs:

- Fallback sealing is static-static ECDH on it (`Crypto+Manager+KeyDerivation.swift:56`).
- The receiver finds the sender by `SHA-256(senderPub ‖ nonce)` over the same key (`OccultaBundle.swift:22`, `Contact+Manager.swift:1523`).
- ML-KEM has no published key either. `quantumKeyMaterialEncrypted` holds the two shared secrets and ciphertexts from the live exchange (`Contact+Model.swift:359–363`), so no post-quantum key exists that a third party could forward.

The `Scopes` enum (`.crypto` / `.sign`, `Contact+Model.swift:393`) sketches exactly this split. `scopes` always returns `[]`, so nothing reads or enforces it.

### D-02 · Changing what a key is for doesn't change what vouching asserts

What was rejected ([Multi-Device Contacts/FINDINGS.md](../Multi-Device%20Contacts/FINDINGS.md), "Rejected: self-vouching device certs"; `ROADMAP.md:140`) is the claim *"this key belongs to this person"*, made by someone else and without meeting. The claim is the same for an encryption key. If it's wrong, Carol's messages go to whoever holds the key. That's a loss of confidentiality, which for a messenger is the worse failure, not the milder one.

The "anonymous" label is also on the wrong side. The risk is Carol's (is this really Bob's key?), not Bob's (who is Carol?). Users will also read "anonymous" as a privacy feature ("my identity is hidden"), not as a warning.

### D-03 · Forwarding an existing key fails on five counts beyond the principle

Forwarding a contact's existing key to people they have never met has five problems:

1. **Coercion reaches further.** Someone holding Alice's unlocked phone can already pose as Alice. With forwarding, they can also introduce a fake "Bob", "Dave" and so on to all of Alice's contacts. That's the one-ceremony-versus-every-contact gap that decided the device-cert ruling (`Multi-Device Contacts/FINDINGS.md:148`).
2. **Bob loses control of his key.** A public key is data. Once forwarded, it can be forwarded again, and Bob can't recall it.
3. **Seized phones leak the graph.** Bob's key, and the record of who introduced him, sit on phones of people he never met, outside his duress depths.
4. **A way in for strangers.** Today `decryptSealed` rejects an unknown sender before decrypting anything (`Contact+Manager.swift:1576`). Accepting anyone who holds Bob's key removes that.
5. **No forward secrecy, or shared prekeys.** Carol has no prekeys for Bob. If Alice forwards hers, one per-sender pool is shared between two senders. That's the historical prekey-batch flaw (`Docs/Audit/CRYPTO_REVIEW_CHECKLIST.md` §3), and the reason the anonymous source drop was omitted (`Master Feature & Expansion Analysis.md:481`).

**Not recommended in this form.**

### D-04 · What survives: the owner issues the card, the contact only carries it

Bob makes a single-use card for someone he hasn't met. He gives it to that person himself, or asks a contact to pass it on. Nobody else can make a card for Bob, and a card says nothing about Bob that he didn't put in it.

Measured against D-03:

1. A coerced Alice can still hand Carol a fake card. Every kind of introduction has this problem (see [Guarantees and limits](#guarantees-and-limits)). But Alice can't create real cards for Bob.
2. Bob chooses who gets each card (§3), and each card works once.
3. No identity key and no name travel on the card.
4. Bob's phone accepts a stranger only if they use a card Bob made.
5. Each card carries its own key, and no one else's prekeys are shared. Since 2026-10-16 the card carries no prekeys at all: prekeys flow once the conversation starts ([SPEC.md](SPEC.md) §1).

Is this vouching? No third party signs or asserts anything, and no trust is granted: the contact stays Not verified until a UWB exchange. D1 rules that this keeps the carrier route on the right side of the line (Q-01, decided 2026-10-15).

It is also not H5's rejected "key-in-bundle" shortcut (`USER_ENGAGEMENT_FRICTION.md:156`). No session key ever travels next to its ciphertext. And the upgrade happens only in person, so the *"reply with your real key so we can go secure"* moment, where an attacker would insert themselves, doesn't exist.

### D-05 · How this differs from Sweep 4's contact card (component 1)

| | Sweep 4 contact card | Introduction card |
|---|---|---|
| Carries | Long-term public key + signed prekey batch | Its own card keys (agreement and signing) + one ML-KEM key + expiry, signed by the card key. No prekeys since 2026-10-16 |
| Who can use it | Anyone holding it, repeatedly | The first person to use it, once |
| First-message forward secrecy | Signed-prekey level (static prekeys) | Same as contacts who met in person: none on the receiving side until prekeys flow (since 2026-10-16) |
| Identity key leaves the phone | Yes | No |
| Cards linkable to each other | Yes (same long-term key) | No |
| Posting one publicly | Discouraged | Pointless: only the first user gets through |
| Component 4 (introductions) | Mutual forwards both keys, signed | Mutual carries the owner's card and asserts nothing |

Sweep 4's "known nuance" was answered at first with a one-time prekey on the card. **Since 2026-10-16 the card carries none** ([SPEC.md](SPEC.md) §1). Carol's messages before she holds Bob's batch are sealed to his card agreement key, so they aren't forward-secret on Bob's side. That's the same as the first messages between contacts who met in person, and the secrecy label says so.

---

## Design

### 1. The identity key still leaves the phone only in person

Each card has its own new Secure Enclave key made for that one relationship: the **card key**. Until the two people meet, it stands in for the identity key on both sides. The sender fingerprint is computed over it, and long-term fallback seals to it.

What this preserves:

- **The trust graph keeps its meaning.** Everyone who holds Bob's identity key has met Bob, so the no-vouching invariant holds literally.
- **Cards can't be linked to each other or to Bob.** Two seized phones holding cards from Bob show two unrelated keys.
- **`#22`'s premise still holds.** It reads *"Occulta public keys … never travel in cleartext, [so] membership probing is only possible for keys the prober already physically collected"* (`Master Feature & Expansion Analysis.md:379`). An identity key on a card would end that, because anyone holding a card could probe for Bob as a mutual contact.
- **Features that need a verified key refuse by default.** Card keys are stored outside `contactPublicKeys`, so every feature that reads a verified key finds none. This answers [Remote Key Exchange](../Remote%20Key%20Exchange/FINDINGS.md) D-06 (no record of how a key arrived) by construction for this path.

**Cost.** Today the user has one key of their own (`Identity.Profile.masterKeyTag`, `Identity.swift:34`), and every send path assumes it. Card contacts need "which of my keys do I use with this contact". This is the largest engineering item (Q-08).

**Rejected alternative: put the identity key on the card.** It's much simpler, since existing code works and the in-person upgrade is a key comparison. It also allows checks before the two people meet: mutual contacts already hold Bob's real key, so gossip (Sweep 4 component 3) and `#22` corroboration could catch a swapped card early. It costs all four properties above. Q-08 records this trade so it gets decided, not drifted into.

**Rejected alternative: sign the card with the identity key, with a nonce** (raised 2026-10-15). It costs the same four properties as putting the key on the card, and gives Carol nothing she can check:

- **Carol can't verify it.** She doesn't hold Bob's identity key until they meet.
- **The signature exposes the key.** CryptoKit signs with ECDSA, and an ECDSA signature plus the signed message yields the signer's public key, up to a couple of candidates. So two seized cards link to each other and to Bob, and `#22` probing works again.
- **It leaves proof on someone else's phone.** Carol's phone would hold a non-repudiable proof that Bob issued the card, outside his duress depths and checkable by anyone who holds his key.
- **The nonce changes nothing.** It changes the signed message, not the key, so the key can still be recovered. A card doesn't need it to be unique either: the card key is new, and Bob's phone redeems a card only once.

The in-person check (§5) already makes this link, and makes it only when they meet.

A hiding commitment instead of a signature, `SHA-256(identityPub ‖ nonce)` with the nonce revealed at the meeting, would be unlinkable but proves nothing. Alice holds Bob's identity key, so she could put the same commitment on a swapped card, and only the §5 card-key signature would catch it.

### 2. What a card contains

> **Superseded in detail by [SPEC.md](SPEC.md) §1–§2 (2026-10-16).** The card holds two card keys, an agreement key and a signing key, because CryptoKit's Enclave keys are typed and a tagged keychain key per card would show how many exist. Since 2026-10-16 it carries **no prekeys**. Prekeys start flowing in the conversation, as they do between contacts who met in person, which also removed the prekey-ID linkage. Its fixed size is 1,770 bytes. The table below is the earlier design: the prekey rows no longer apply.

| Field | Why |
|---|---|
| Card key, public half (P-256, Secure Enclave) | Bob's identity in this relationship until they meet |
| ~~A batch of one-time prekeys~~ (decided 2026-10-15, **dropped 2026-10-16**: the card carries no prekeys, SPEC §1) | Forward secrecy for Carol's messages until Bob replies, so she doesn't have to wait for him. The first one used redeems the card and makes it single-use (§3). It costs about 1 KB of card size and as many Enclave keys as an ordinary batch |
| One ML-KEM-1024 encapsulation key (iOS 26+) | Post-quantum protection from the first message (`Multi-Device Contacts/FINDINGS.md` D-08) |
| Expiry | Limits how long a lost or intercepted card stays usable |
| Card key's signature over all of the above, with its own domain-separation prefix | Without it, someone on the route could swap just the ML-KEM key (or, in the earlier design, a prekey), read the first message and re-seal it to Bob's real key. The in-person check (§5) would still pass, because the card keys match |

**A card contains no name, no photo, no identity key, and nothing that names the carrier.** Carol learns who it's from through the route it arrived by.

### 3. How a card is used (contact-first, decided 2026-10-15)

A card belongs to a contact Bob already has but hasn't exchanged keys with. The app already has these: a contact with no keys shows as "pending" (`Contacts+DesignTokens.swift:115`).

1. **Bob creates a card from the contact's details.** It is stored in a fixed-size encrypted field on the contact record, which every contact has (Q-05). The field holds the private halves of the card keys and the ML-KEM key, as Enclave blobs (as prekeys are held under Prekey Continuity D9). **A contact has at most one active card.** Creating a new one cancels the old one and deletes its record and keys. Otherwise two cards for Carol could both be used, one by Carol and one by whoever intercepted the other, and two conversations would claim the same contact.
2. **Bob shares it** through any channel he chooses (§4, W-02).
3. **Carol imports it, and goes straight on to write.** The import sheet's main button is **"Import and write to {Name}"**. It imports, then opens the contact with compose focused and the countdown and secrecy label in view. "Import only" is the secondary choice. The same flow continues in the app from the share extension (decided 2026-10-16). Carol attaches the card to one of her contacts or a new one, and the contact becomes Not verified. **What happens depends on that contact** ([SPEC.md](SPEC.md) §6.3):
   - **Already waiting on an earlier card from Bob:** the new card **replaces** it. Bob can only issue a card from a pending contact, so a new card means his side never got Carol's message, or he discarded the conversation. Carol never has to give up and start over, because Bob is the one who issues cards.
   - **Already in a card conversation with Bob:** **refused** (W-16). Someone could send a card claiming to be from Bob, and it must not replace a live conversation.
   - **Carol's own card is out to Bob** (both made cards, and they crossed): **key order decides** (decided 2026-10-16). Both phones hold both cards, so they agree without asking: the card with the lower agreement key survives. If Bob's wins, Carol's phone cancels her card and imports his. If hers wins, the import is refused (W-17), and Bob's phone cancels his card when he imports hers. One card at a time between two people, and no deadlock. Other rules were weighed:
     - importing cancels your own card: stuck whenever both import, which is the likely case, since both received a card in the same chat;
     - asking the user: stuck if both cancel;
     - keeping both cards until a conversation forms: always works, but grows the card field on every contact from 12 KB to 16 KB.

     Key order's one weak case is when only the side whose card wins imports, and the other never does. It heals when the cards expire after a day.
4. **Carol sends a first message within the day.** The first message is what activates the card, and only its deadline is enforced (Q-05). It is sealed with an ephemeral key to Bob's card agreement key, with ML-KEM encapsulated to the card's key ([SPEC.md](SPEC.md) §4.3). The payload carries Carol's own new card key, a prekey batch and an ML-KEM encapsulation key, all signed with her card key. That signature plays the role the sender's ephemeral signature plays for last-resort sealing in groups (`Prekey Continuity/DESIGN.md` §3.1). Without it, anyone holding the card could claim any card key, and §5 couldn't tell who wrote the first message.
5. **Bob's phone recognises it.** When `identifyOwner` matches no contact, the receive path tries Bob's pending cards before failing. There is no cap on the number of active cards, but each one expires after a day, so few are active at once and the cost stays small (Q-05). If a card opens, it is redeemed. The conversation attaches to the contact the card was made from, which becomes Not verified. After that, Bob's phone accepts only Carol's card key on this contact. A message from any other sender matches no contact, finds no active card, and fails like any message that can't be opened. So the card still works exactly once.
6. **Either of them writes, whenever they like.** With no time limit after the first message, Carol can keep writing before Bob replies. Those messages are sealed to his card agreement key, and labelled Standard Encryption until she holds his batch ([SPEC.md](SPEC.md) §6.5). Bob has Carol's prekeys from her first message, so he can write at any time. Bob's first reply uses Carol's prekeys and encapsulates to her ML-KEM key. After these two messages the pair holds two ML-KEM secrets, as after a ceremony, and forward secrecy works per contact as it does for verified contacts.
7. **The card is spent.** From here on the conversation runs on the two card keys and the prekeys exchanged inside it, until they meet (§5).
8. **Ending without a meeting.** An unused card expires or Bob cancels it, and its record and keys are deleted. If Carol tells Bob, through another channel, that Carol's message never arrived, then the message that did arrive came from someone else. **Bob discards the conversation** under "Wasn't Carol?" on the contact's details (W-15). The card conversation's keys are deleted, the contact returns to pending, and Bob can make a new card.

**How a contact moves between tiers (2026-10-15):**

| Tier | Keys | Can message |
|---|---|---|
| Pending exchange | None, just a name and details | No |
| Not verified | Card keys, with no in-person exchange | Yes |
| Verified | Exchanged in person | Yes |

- **On Bob's phone,** Carol stays Pending while the card is out and unused. She moves to Not verified when her first message arrives.
- **On Carol's phone,** importing the card moves Bob straight to Not verified, because Carol can send to him from then on.
- **On both phones,** the in-person exchange moves the contact to Verified.
- **A pending contact with an active card stays in the Pending list**, and its row shows a second line: **"Card · 23h 12m 05s"**, a live countdown ticking every second, the same clock as the details screen ("timer at all times", decided 2026-10-17). On Carol's phone, a contact waiting for her first message shows **"Send by · 23h 12m 05s"**. Past the deadline, both the line and the countdown show **"Expired"** until the sweep clears the card. This reverses the earlier "only the contact's details show the card" (2026-10-16). It makes a card in progress visible where people look, adding urgency. It is shown only at the depth where the contact is visible, like everything in the list.
- **Bob can reply right away (decided 2026-10-16).** The first-message view has a **"Reply to {Name}"** button that opens compose. A note says the reply gives {Name} Bob's prekeys, so {Name}'s next messages are forward-secret. It mirrors Carol's "Import and write".
- **All card content sits in one section on the contact's details (decided 2026-10-16).** Status (W-06), countdown or deadline, waiting state, and the card's actions (Share, Cancel, "Wasn't {Name}?" with Discard) go in one "Introduction card" box and are never split across the screen. On a pending contact it follows "No key yet", as the alternative to meeting. On a Not verified contact it comes right under the name, followed by compose, and "Meet {Name} to verify" goes last.
- **A live countdown** replaces the static date wherever a card is pending: "Expires in 23h 12m" on Bob's active card, and on Carol's deadline notice for Bob's contact (decided 2026-10-16).
- **Carol's phone clears a dead card on its own** in the unlock sweep, at every depth: past the deadline with nothing sent. If she sent something, it keeps waiting for Bob's reply, because his reply may still come. There's no timer and no discard for Carol ([SPEC.md](SPEC.md) §6.4).

**The details view shows only the active card, if there is one.** Used, expired and cancelled cards leave nothing behind, so the phone keeps no record of the introductions it issued.

### 4. Delivery routes

**v1 is direct only (decided 2026-10-15).** Bob shares the card himself, in person or through a channel he chooses. The risk is that the channel keeps a copy, and whoever controls the channel can use the card first (W-02). The rest of this section describes routes that are **deferred until direct cards have shipped**:

- **Carriers of any length**, including a single carrier. Chains could serve a sender and a receiver who want to stay anonymous to each other while an intermediary delivers. Such a pair never meets, so their contact stays Not verified permanently.
- **Open cards.** They have little use unless published for anyone to take, and a published card works once, for whoever uses it first.

D1 (Q-01) is decided, so carriers are allowed when they're built.

| | Through carriers (deferred) (Alice, and anyone after her) | Shared directly by Bob |
|---|---|---|
| Who could swap the card | Any carrier on the route, or someone holding one of their unlocked phones | Anyone controlling the channel: the messaging app, the email account, a phone or cloud backup |
| Where the card file ends up | Inside Occulta bundles, unless a carrier shares it outside Occulta (Q-13) | The other app's storage and its cloud backups |
| Third party involved | Yes; allowed under D1 (Q-01) | No |
| Best for | Someone Bob can't reach privately, or doesn't know yet | In person, or a channel Bob already trusts |

**Through carriers.** Bob sends the card to Alice inside an ordinary bundle. Whoever holds the card can use it or pass it on. Each holder's copy is deleted when they pass it on.

**The card is identical at every hop.** It's signed by Bob's card key, so a carrier can't add to it without breaking the signature. Nothing in it records who carried it or how many people did. Anyone holding a copy, at any point on the route, sees the same bytes.

**Named and open cards (decided 2026-10-14; deferred 2026-10-15).** Bob chooses one when he creates the card:

- **Named:** meant for one person. Bob hands it over himself, or asks a carrier to give it to that person. Bob chooses the recipient.
- **Open:** for whoever the carriers think should be able to reach Bob. Bob chooses only the first carrier, and the recipient is decided by people he may not know. Single use and the cap on pending cards (Q-05) still limit how many strangers can reach him at once.

What this costs, stated plainly:

- **Every carrier is someone who can swap the card.** The more carriers on the route, the more people the recipient's trust rests on, and none of them can be identified afterwards.
- **For an open card, the recipient knows whose card it is only from what the person who gave it said,** and that may itself be second-hand. A card carries no name, so the owner's identity is relayed by word of mouth at every hop until the in-person check.
- **The mode guides honest apps; it can't be enforced.** A modified app can pass on a named card. Single use is the real limit.

**One badge for every route, with no route text (decided 2026-10-15, Q-07).** The earlier recommendation showed the route as text; that part was dropped (Q-07 gives why). With two near-identical badges, the stronger one starts to read as safe, and users can't weigh carrier risk against channel risk anyway. `CONSUMER_OPENING_AND_CEREMONY.md` D3 argues the opposite for two in-person rungs, but those differ in how rigorous the user's own check was. These routes differ only in who could have swapped the card, and the user did no check on any of them.

### 5. Meeting in person: checking the earlier conversation

Bob opens Carol's contact and taps Exchange keys, as with any pending contact. **There is no picker:** the user chose the contact by opening it (Q-10).

The card itself doesn't matter by now; it was spent when it was used. What remains is the pair of card keys the remote conversation ran on. **The exchange always completes:** the contact gets the real keys, verified in person, whatever happens next. If the contact has a card conversation, the UWB ceremony adds one check, which answers one question: *was the person I was messaging this person?*

1. Each side signs the ceremony transcript with its card key for this contact.
2. Each side checks the other's signature against the card key it holds for this contact.

- **Match (W-12).** The app can truthfully say every earlier message went to this person:
  - Carol's card key signed her first message (§3 step 4).
  - Carol sealed her first messages to Bob's card agreement key, which his signed card carries (§2).
  - Everything after that used prekeys exchanged inside those authenticated messages.
- **Mismatch (W-11).** Everything exchanged with this contact before the meeting went to someone else.
- **Either way,** the card keys are deleted on both sides. After a mismatch, that cuts off whoever was on the other end.
- **No card conversation** (the card was never used): a plain exchange. Any active card is cancelled.
- **The two phones can be in different states when they meet (decided 2026-10-17).** If Carol has written but hasn't seen Bob's reply, Bob is in a conversation while Carol is still waiting. So each phone signs whenever it holds a card key for the contact, and shows a verdict whenever earlier messages exist: Bob in a conversation, and Carol once she has sent something. A phone that signed only from a conversation would give Bob a false W-11. In every case the contact ends up Verified with the card cleared. The full table is in [SPEC.md](SPEC.md) §7.

Without this check, the exchange would quietly upgrade the contact. A conversation with whoever swapped the card would then read as one continuous conversation with Carol, and the user would never learn that what they sent earlier went to someone else.

Sweep 4's caveat still applies: *"verification detects; it does not rewind."* The gain is precision. Instead of learning that something might have been exposed, the user learns exactly which conversation was.

### 6. What a Not verified contact can't do

These are hard gates in code, not badges, following Remote Key Exchange D-06 and Q-04:

| Feature | Why it's blocked |
|---|---|
| Vault trustee | Shards distributed to a swapped key can't be recalled (`Remote Key Exchange/FINDINGS.md` Q-04) |
| Shard content | Needs a verified recipient; long-term fallback already drops it (`Contact+Manager.swift:1624`) |
| Payment cards | Their value rests on physical provenance (`Payment Cards/FINDINGS.md:298`) |
| Identity challenge, Presence Verification | There's no identity key to challenge |
| Groups | Adding one would expose every member to a key nobody has verified |

Storing card keys outside `contactPublicKeys` (§1) should make each of these refuse by default. Each still needs a test proving it does.

The cipher suite matches verified contacts, so Sweep 4's invariant *"identical cipher suite at every rung"* holds. Cards require iOS 26 at both ends (Q-06), so no classical-only card exists.

---

## Warnings: what can go wrong, said where it can go wrong

### Rules

These carry over from earlier decisions:

- **Always shown, never behind a tap, never a dismissible dialog.** From Sweep 4: *"warning fatigue is the primary failure mode … a persistent per-contact badge visible in the contact list, at compose, and at send — never a one-time dialog."* H5 adds that click-through warnings *"train users out of reading the app's security signals."* The working model is the compose `SecrecyIndicator` (`Prekey Continuity/DESIGN.md` §7): a label and a description, always visible.
- **Name the failure and the action.** Each warning says what could happen ("someone else could read these messages") and what to do ("verify in person before sending anything sensitive"). Never use "secure", "safe", "anonymous", shields or checkmarks.
- **Claim no more than the design delivers** (`Docs/Audit/OPEN_LIMITATIONS.md` §E).
- **Name the person, never "them" (2026-10-15).** Copy uses `{Name}` wherever it refers to the other person. Where no name exists yet, such as a new contact being created at import, it says "the sender".
- **Say the channel can be compromised (2026-10-15).** The card travels through another app, so the copy says that app or the account could be compromised. That's why Not verified contacts call for care with what you send until you meet and exchange keys in person.
- **State the deadline wherever a card is pending (2026-10-15; wording revised 2026-10-16).** Both sides see the date by which the first message has to **reach Bob**, not be sent, and that there's no time limit after it. Bob's phone checks the deadline when it opens the message (SPEC §6.4). The deadline is shown: Bob when creating, sharing and on the active card, Carol when importing and before sending.
- **Same text at every depth.** Text depends only on the contact's or card's own state, never on the current depth (`Prekey Continuity/DESIGN.md` §7).
- **Secrecy and trust are separate lines.** A Not verified contact's next message can be forward-secret. The `SecrecyIndicator` green is the `occultaVerified` token, and Sweep 4 rules that *"nothing about an unverified contact may render green or 'secure'"*. So for a Not verified contact, the trust line comes first and the secrecy state isn't green (Q-09, decided).
- **The alarm can't be missed (revised 2026-10-15, Q-10).** W-11 is shown at the exchange and needs an explicit acknowledgment. It can't be swiped away or skipped. Nothing is stored afterwards. This replaces the earlier rule that the contact keeps a "Card swapped" state. That rule was written for a mismatch that left the contact pointing at the attacker. Now the contact ends up verified with the real person, the danger is past, and a stored state would only be a trace. W-11 is the one warning that appears as an event rather than a persistent label, because it reports something that happened, not a risk that is still open.

### Draft copy

Placeholders:
- `{Name}` is the user's own label for the contact.
- No route placeholder: neither the carrier nor the route kind is shown or stored (Q-07).

| # | Where | What can go wrong | Draft copy |
|---|---|---|---|
| W-01 | Creating a card from a contact's details (issuer) | Whoever uses the card first becomes "{Name}" to you | "Anyone who gets this card before {Name} can use it and pretend to be {Name}. Share it only with {Name}. {Name}'s first message must reach you by {date}, or the card stops working. Making a new card cancels this one." |
| W-02 | Sharing it directly, before the share sheet (issuer) | The channel keeps a copy, or is compromised, and whoever controls it can use the card first | "The app you send this through keeps a copy, possibly in its backups, and that app or the account could be compromised. Anyone who can read that chat could use the card before {Name} does. Once the card is used or expired, a leftover copy is useless." Shown with the deadline: "{Name}'s first message must reach you by {date}. After that the card stops working, and you'd need to make a new one." |
| W-03 | *Deferred (carriers).* Asking a contact to pass a named card on (issuer) | The carrier gives {Name} a different card | "{Carrier} will be able to see this card and could give {Name} a different one. Only ask someone you'd trust to introduce you in person." |
| W-04 | *Deferred (carriers).* Receiving a card from its issuer to pass on (first carrier) | It goes to the wrong person | "{Sender} asked you to pass this card on. Whoever you give it to can message {Sender} once. It is removed from your phone when you pass it on." |
| W-05 | Importing a card (recipient) | The card was swapped on the way, or isn't whose you were told | "Not verified. You know whose card this is only from the chat it arrived in. If that app or account was compromised, the card could have been swapped, and your messages would go to whoever swapped it. Be careful what you send until you meet {Name} and exchange keys in person." Shown with the deadline: "Must reach {Name} by {date}. Your first message has to reach {Name} by then, or the card stops working. Send it early enough for {Name} to open it in time. After that, there's no time limit." |
| W-06 | Contact list, contact screen, compose, send (both); persistent. Also for shared or transferred keys (Q-14) | Same as W-05 | Badge: "Not verified". Description: "You haven't met and exchanged keys in person yet. If the app the card traveled through was compromised, someone else could be reading this conversation. Be careful what you send until you meet." **Where it shows (decided 2026-10-16):** the chip next to the name everywhere, and the trust line as the first item of the card section on the contact's details. Compose sits directly below the card section, so it doesn't repeat the line; the chip and trust line stay in view while writing, which covers "at compose" and "at send". |
| W-07 | After the first send (recipient) | Someone used the card first, so no reply will come | "Waiting for the first reply. If none comes, someone may have used this card before you. Ask {Name} for a new card. It replaces this one." |
| W-08 | First message arrives (issuer) | Whoever used the card first wrote it | "First message on your card for {Name}. Whoever used the card first wrote it. That's probably {Name}, but you can't be sure until you verify in person." |
| W-09 | Active card, on the contact's details (issuer) | A lost card can be used until it expires | "Not used yet. {Name}'s first message must reach you by {date}, and then the card stops working. Until then, anyone who has this card can use it. Cancel it if it might have reached the wrong person." |
| W-10 | A blocked feature (both) | — | "{Feature} needs a contact you've verified in person, because it relies on knowing this key really is {Name}'s. Meet {Name} and exchange keys to verify." |
| W-11 | Mismatch at the in-person check (both) | The earlier conversation was intercepted | "Before today, you weren't messaging {Name}. Someone swapped the card on its way and could read everything you sent. You're now connected to {Name}, verified in person, and whoever was on the other end has been cut off." |
| W-12 | Match at the in-person check (both) | — | "Verified in person. Your earlier messages with {Name} went to this person." |
| W-13 | *Deferred (open cards).* Creating an open card (issuer) | The card goes to people you don't know, and any of them can swap it | "This card can be passed on by {Carrier} and by anyone they give it to. You won't know who ends up with it, and any of them could use it or swap it. It works once and stops working on {date}." |
| W-14 | *Deferred (carriers).* Receiving a card from a contact who isn't its issuer (holder) | The holder can't tell whose card it is | "This card was passed on to you. You know whose it is only from what you were told. You can use it yourself or pass it on. Whoever uses it can message its owner once." The carrier isn't named (Q-07); the message it arrived in shows its sender as any message does. |
| W-15 | Discarding a card conversation, under "Wasn't {Name}?" on the contact's details (issuer) | The card was used by someone other than {Name} | Always visible: "If {Name} never sent the first message you got, someone else used your card before {Name} could, and that's who you've been talking to. Discard this conversation and make {Name} a new card." Confirmation: "Discard the conversation with {Name}? Whoever used your card is cut off. {Name} goes back to pending, and you can make a new card." |
| W-16 | Importing a card for a contact already in a card conversation (recipient) | A card claiming to be from {Name} would replace a live conversation | "You're already talking with {Name} through a card. Meet {Name} to verify instead." The import is refused. |
| W-17 | Importing a card for a contact who has the user's own card, when the user's card wins on key order (recipient) | The cards crossed. The other side has to import the user's card | "You already sent {Name} a card. Wait for {Name}'s message. {Name} needs to import your card." The import is refused. When the other card wins, the user's card is cancelled and the import goes ahead with no message. |
| W-18 | Importing the user's own card (recipient) | A person would start a conversation with themselves | "This is your own card." The import is refused (decided 2026-10-17). |

W-01 and W-03 also counter H5's downgrade point: *"attackers don't break crypto — they social-engineer victims into the weak mode."* The weak mode here is a card. An attacker posing as someone can ask the user for one, so the moment the user creates a card is where the risk is stated.

---

## Guarantees and limits

**Guaranteed, if built as above:**

- No general way in. Only someone using a card Bob made can start a conversation with him.
- Bob chooses who gets each card, one active card per contact. A card works once and expires.
- Nothing records the route. The card is identical at every hop, and no carrier's identity is written anywhere.
- Forward secrecy for the first message, and hybrid post-quantum protection on iOS 26+.
- Carriers and channels never see message content.
- Bob's identity key never leaves his phone except in person.

**Limits.** These are inherent or open; none is accepted.

- **A coerced or dishonest carrier can substitute a card.** Every kind of introduction has this problem, and no design closes it. Only the in-person check (§5) detects it. No mutual contact holds the card key, so gossip (Sweep 4 component 3) and `#22` corroboration can't check it earlier. That is a direct cost of §1.
- **Whoever uses the card first wins.** Until they meet, the first message proves only that whoever used the card first sent it. Someone who uses an intercepted card becomes "{Name}". The real recipient's message then fails like any bundle that can't be opened, and the only sign is W-07. Anyone holding an unused card can also use it up.
- **Verification doesn't undo exposure.** Messages sent before a mismatch was found were readable.
- **Cards become what attackers ask for** (H5's downgrade point). Mitigated by W-01 and by the permanent badge. Not closed.
- *The next three apply to the deferred carrier routes (§4).*
- **More carriers, more people who can swap.** Each carrier on an open card's route is someone the recipient's trust rests on, and none can be identified afterwards (§4).
- **Whose card it is travels by word of mouth.** A card carries no name. The recipient believes it's Bob's because the person who gave it said so, and on an open card that may be second-hand.
- **Named versus open can't be enforced.** A modified app can pass on a named card. Single use is the only hard limit.
- **No help for people who aren't on Occulta.**
- ~~Anyone holding the card can link Carol's first messages to it~~ (recorded 2026-10-16; **no longer applies** since the card carries no prekeys, [SPEC.md](SPEC.md) §4.6).

---

## Forensic and coercion review

| Observer | What they learn |
|---|---|
| Finds a card file (another app's backup, a Files folder) | Three public keys, an expiry and a signature. No name and no identity key. Nothing in the file names Occulta (Q-04), but someone who knows the format can confirm it's a card by verifying its signature. An unused, unexpired card can be used once. It doesn't identify Carol's first messages: they carry a random `prekeyID` (SPEC §4.6). |
| Seizes the recipient's phone | A Not verified contact under a card key, with no record of how the card arrived. It can't be connected to the issuer's identity key or to other cards. The seizer can message the issuer as that contact, as with any contact on a seized phone. |
| Seizes two phones holding cards from the same issuer | Two unrelated keys. Verified contacts all hold one identity key, so cards are less linkable than verified contacts. |
| Seizes a carrier's phone | Nothing of the card once it was passed on. With the phone unlocked, they can give the carrier's contacts fake cards. That reach is limited to that contact list, and each fake is caught at its in-person check. |
| Holds a copy of a card anywhere on its route | The same bytes at every hop. Nothing shows who carried it or how many people did. |
| Images the issuer's phone | Every contact record carries a fixed-size encrypted card field, filled with random bytes when there's no card. The number of active cards isn't visible (Q-05). |
| Coerces the issuer at a duress depth | Q-03. |

---

## Considered and not adopted

Both ideas below came up on 2026-10-14 as ways to know who passed a card on. Both fail the same way. **The record is either forgeable, so it proves nothing, or signed, which makes it vouching and leaves evidence.** And whoever needs to know already does, or can be told.

### C-01 · The carrier's identity key inserted into the card

The aim was for the recipient's or the issuer's phone to know which contact passed the card on.

- **They already know.** On the carrier route, the card arrives inside an ordinary Occulta message, and the app identifies that message's sender as it does every message. Bob labelled the card when he handed it over, and each card works once, so the card that opens tells him its route.
- **A bare public key proves nothing.** Anyone can write Alice's key into a field, so the app would have to ignore it.
- **A signed entry is vouching.** An already-trusted key signing something that introduces a new key is the rejected pattern, and D-04's defence of carriers is that they assert nothing.
- **A signature doesn't stop a dishonest or coerced carrier.** They sign their own fake card just as easily. The signature proves which phone did it, not which person.
- **A signature is evidence.** An unsigned note is deniable, since anyone could have typed it. A signature from Alice's Secure Enclave key proves, to anyone who checks it, that Alice connected Bob and Carol.
- **It invites a trust tier.** "Introduced by Alice ✓" reads as more trustworthy than a direct card. That's the Introduced rung again.

### C-02 · An encrypted chain of carriers, readable only by the issuer

The idea was that the card carries a public key belonging to Bob. Each carrier appends an entry encrypted to it, so only Bob can read the route the card took.

- **Forgeable or signed.** Each carrier writes their own entry. Unsigned, any carrier can write anything or remove earlier entries, including the one who swapped the card, which is the only case where the chain would matter. Showing Bob a route that could be fake claims more than the design delivers. Signed, it's C-01's vouching and evidence, for every hop.
- **Encrypting to Bob hides the chain from the wrong people.** Carriers and the recipient can't read it. But Occulta is built against someone who seizes or forces open a phone, and Bob's phone decrypts the chain for whoever unlocks it.
- **It gathers every route in one place.** Every card Bob issues leaves its full route on his phone, which is often the most targeted one. For a journalist hearing from sources, the chain is a list of the people who helped a source reach them, and that list otherwise exists nowhere.
- **It tells Bob about people he never met, without their choice.** An entry for Dave needs an identifier, and each option fails:
  - Dave's identity key leaves his phone for someone he never met, which breaks §1's invariant and #22's premise.
  - A fingerprint means nothing to Bob, but it's a stable identifier a coercer can match across seized phones.
  - A name is self-declared and proves nothing.
- **Its size reveals the number of carriers,** unless it's padded to a fixed maximum, which caps the route.

**What replaces both:** nothing in the format. If Bob wants to know how someone reached him, the recipient can say so in their first message, in their own words. That's deniable, it's their choice, they can leave people out to protect them, and it isn't a stored record, since received messages aren't kept after closing (`Message Persistence/FINDINGS.md`). **That last point holds only while message history is unshipped,** so revisit this if it ships.

---

## Open questions

### Q-01 · D1: does the carrier route cross the no-vouching line? (decided 2026-10-15: carriers allowed, deferred past v1)

The docs currently disagree on D1:
- **Open:** `USER_ENGAGEMENT_FRICTION.md` (Sweep 4 item 4) and `CONSUMER_OPENING_AND_CEREMONY.md` §7.
- **Off-limits:** `Master Feature & Expansion Analysis.md:571` and `Feature Ideation — 2026-07-10 Community Demand Pass.md:118` say "re-affirmed as off-limits".

Those last two entries describe verified introductions, where a mutual contact vouches. The carrier route here asserts nothing and grants nothing (D-04). Decide, then align all four docs.

**Decided 2026-10-15: the carrier route is allowed.** Passing a card on isn't vouching:
- Nothing is signed, and nothing records the route.
- No trust is granted: the contact stays Not verified until a UWB exchange.
- The only claim is spoken ("this is Bob's card"), like passing on a phone number.

The two off-limits entries now say that carried cards are outside them, and that verified introductions stay off-limits. The two Friction addenda record the decision.

`Remote Key Exchange/FINDINGS.md` Q-01 applies here unchanged: a Not verified tier makes public claims such as *"No one can impersonate you remotely"* (`README.md:15`) conditional on the contact's tier. That has to be settled before shipping, not after. It applies to the direct route too, so it stays open after D1: the `README.md` wording changes in the same change that makes cards reachable.

### Q-02 · D2: send-capable or import-only?

This design assumes send-capable, with W-05 and W-06 carrying the risk. Import-only would require a remote SAS (the Confirmed rung, `Remote Key Exchange/FINDINGS.md`) before the first send. That removes the first-contact swap risk but loses the asynchronous first message. Still open.

**Decided 2026-10-15: send-capable.** For cards, import-only has no purpose; it didn't lose a trade-off. D2 came from Sweep 4's multi-use contact card, where it means "save the long-term key now, and send once a code is compared on a call". That works between people who know each other's voices. For a card:

- **The remote check proves nothing.** Carol has never heard Bob's voice. Whoever swapped the card can take the call, and the codes match, because the key really is theirs.
- **Waiting to meet makes the card pointless.** The UWB ceremony exchanges the real keys anyway.

The risk is carried by W-05, W-06 and W-07, as designed.

### Q-03 · Duress (decided 2026-10-15: cards follow their contact's depth)

The shipped rule says no bundle is rejected because of the current depth, and an unrecognised sender fails the same way at every depth (`Docs/Bugs/v1.10.0/Non-Safe-Sender-Rejection-Is-A-Duress-Detection-Oracle.md`, final design 2026-08-08). Applied to cards:

- Creating a card at a duress depth must work, and the card belongs to that depth (floor semantics, as `originDepth`).
- Redemption must try every pending card regardless of depth, just as `identifyOwner` matches hidden contacts. Otherwise a coercer holding an unused card learns from a failure that the card came from another depth.
- That puts a card redeemed from a hidden depth into the presence-oracle shape recorded 2026-08-13: a message opens from someone absent from the list. Should cards inherit that documented limitation, or behave differently?
- Pending cards stay invisible at depths that didn't create them.

**Decided 2026-10-15: cards follow their contact's depth.** The card lives on its contact (Q-05), so the contact-first flow settles most of this:
- **Creating a card at a duress depth works.** The card belongs to a contact visible at that depth. Nothing in the card records a depth.
- **A hidden contact's active card is hidden with it.**
- **The receive path tries every active card regardless of depth,** as `identifyOwner` matches hidden contacts.
- **Cards inherit the documented presence-oracle limitation, with no new leak shape.** A hidden contact's card used at a duress depth opens a message from a contact absent from the list. That's the presence oracle accepted on 2026-08-13 for any hidden contact (`Docs/Bugs/v1.10.0/Non-Safe-Sender-Rejection-Is-A-Duress-Detection-Oracle.md`). The earlier question of which depth a new card contact appears at no longer arises, because the contact exists before the card.
- **Expiry is checked when a message arrives, at every depth.** A cleanup that only ran on visible contacts would leave a hidden contact's card usable for longer than a day.
- **Cleanup overwrites the card field with random filler of the same size.** It leaves no change on disk.

### Q-04 · Can a card file be unrecognisable?

A card shared directly ends up in another app's storage. If it starts with an Occulta marker, it's the "I use Occulta" evidence that Sweep 4 and `Remote Key Exchange/FINDINGS.md` D-08 warn about. Can a card look like random bytes and still be importable? For example, the app could recognise it by trying it, the way the receive path tries pending cards.

**Decided 2026-10-15: unbranded for v1.**
- **The file:** no magic bytes, no file extension, no registered file type, and a generic file name.
- **How the app recognises it:** the bytes parse, and the card's own signature verifies under its domain-separation label (§2).
- **How Carol imports it:**
  - through Occulta's share extension (`ShareExtension/`), which accepts generic data;
  - or with an Import card button inside the app.

  There is no "Open in Occulta" from a chat.

**Rule for any future unbranded format.** Each format is recognised by its own authenticity check, never by a marker:
- **Each check passes for its own format only.** Every check uses its own domain-separation label, so a card's signature can't verify as another format, and the reverse.
- **The app tries the checks in turn,** and the one that passes says what the file is.
- **Versions follow the same rule.** A new version gets a new label, and the app tries each version's check. There is no version byte, so the list stays short. Each check is a single signature verification or trial decryption.
- **Every format and version gets its own vectors** in `OccultaTests/Interop/InteropVectors.json`.

**Limits (accepted for v1, decided 2026-10-16).** Unbranded stops detection by marker: scanners, backup indexing, someone glancing at the file. It doesn't stop an analyst who knows the format:
- **The signature can be tested.** It has to verify for anyone, because Carol has nothing else to check it against. So anyone who knows the format can verify a suspect file and know for certain that it's an Occulta card.
- **The bytes aren't uniformly random.** The size is fixed, and the ML-KEM key's packed coefficients are below q, which a statistical test detects. A uniform encoding (Kemeleon-style) would remove the second part.

**Possible later option: a code-encrypted card.** Bob encrypts the card under a short code he tells Carol separately. Only someone who has the code can recognise or use the card. It costs a second channel and an extra step, so it isn't in v1.

**Why accepted for v1 (2026-10-16):** only someone who already suspects a file, and knows the format, can confirm it's a card. Both ways to close it cost real work: a code-encrypted card needs a second channel and an extra step for users, and a uniform ML-KEM encoding (Kemeleon-style) needs a careful implementation of its own. Both stay recorded here for later.

### Q-05 · Pending-card storage

The cap and the expiry are product choices; 8 cards and 14 days are placeholders. Since 2026-10-15 a contact has at most one active card (§3), so the cap limits how many contacts can have an active card at the same time. The row count is visible on disk. Preallocated fixed slots would hide it, which is the same question the soft-delete cap answers for contacts.

**Decided 2026-10-15:**

- **The card lives on the contact.** Every contact record carries a fixed-size encrypted card field:
  - with no card, it holds random filler;
  - with an active card, it holds the card's private keys and its expiry;
  - with a card conversation, it holds the two card keys.

  Every row is the same size, so the number of active cards isn't visible on disk, and no separate table is needed. The structure itself enforces one active card per contact. The card also lives at the same depth as its contact, which helps with Q-03. (The comparison above to a "soft-delete cap" points to nothing defined in the docs or the code, so it no longer applies.)
- **One active card per contact, with no limit across the app.** The limit covers unused cards only. Not verified contacts with a conversation in progress are ordinary contacts and aren't limited.
- **Storage refined in SPEC §5 (2026-10-16).** The card field holds the card keys, the ML-KEM key and the state. The card has no prekeys (2026-10-16): each side's batch is made at import or redemption and travels in the conversation. **The deadline is measured when Bob opens the message (decided 2026-10-16, SPEC §6.4).** Carol's send time can't be trusted, so the copy says the first message must reach Bob by the date.
- **Cards expire after 1 day, fixed, with no picker.** That day is how long Carol has to import the card and send her first message, and also how long someone who intercepted it has to use it. After the first message, the conversation has no time limit. The deadline is on the first message, not on importing. Importing happens only on Carol's phone, so Bob's phone can't see it. A deadline checked on Carol's phone can't be enforced, and Bob would have to keep the card's keys until something arrived, which would leave an intercepted card usable for that whole time. Bob's phone enforces the expiry by deleting the card's keys, so a late first message fails like any message that can't be opened. If Carol misses the day, Bob makes a new card.
- **What the receive path costs.** With no overall cap, each message from an unknown sender is tried against every active card. The 1-day expiry keeps that number small in practice.

### Q-06 · iOS 18.6–25

These versions have no ML-KEM, so cards to or from them are classical-only. Options:
- Allow it, with the post-quantum status the secrecy indicator gains in v2.0.0 step 7.
- Require iOS 26 at both ends.

**Decided 2026-10-15: require iOS 26 at both ends.** The in-person exchange needs a U1 chip, so an iPhone 11 or later, and all of those can run iOS 26. The requirement only excludes people who haven't updated. In return:
- there is one card format and one size, which the unbranded rule needs (Q-04);
- there is no weaker mode for an attacker to push people into.

On older iOS:
- **Create card is disabled.**
- **Importing a card fails.** The app still recognises the card, because the signature check is classical.

Both say "Introduction cards need iOS 26 or later", and claim nothing more.

### Q-07 · Should the carrier be named on the recipient's phone?

"Card via Alice" helps the user judge trust, but on a seized phone it's a recorded introduction. Recommendation: store only the route kind. The user can add the carrier to the contact's notes if they choose.

**Decided 2026-10-14: the carrier is never named on the recipient's phone,** in the badge, the warnings or the stored record. C-01 and C-02 record two ways of recording the carrier that were considered and not adopted.

**Decided 2026-10-15: one "Not verified" badge for every route, with no route text, and the route kind isn't stored.** Three reasons:

- **The route kind can't be verified.** A carrier may have got the card from a file, and the app can't tell.
- **Open cards make "passed on by a contact" close to meaningless.** It says nothing about who, or how many.
- **A stored route kind is a record.** On a seized phone it shows that this contact came through an introduction.

The user knows how they got a card. They can add it to the contact's notes if they want it written down.

### Q-08 · Card key or identity key on the card? (decided 2026-10-15: card key)

This is the trade in §1. Recommendation: card key. It keeps the trust graph's meaning, cards unlinkable, and `#22`'s premise intact. It costs per-contact own keys throughout the send path, and the chance to catch a swapped card before meeting.

**Decided 2026-10-15: card key.**
- **The send-path cost** is narrowed by contact-first storage (Q-05) to one check per send: if the contact's card field holds a card conversation, sign and seal with my card key, otherwise with my identity key. It still touches every send path, which makes it the largest engineering item.
- **A Not verified contact shows no fingerprint.** A card-key fingerprint means nothing to compare. Showing one would suggest it can be checked, and the only remote check would be a code compared on a call, which proves nothing between people who have never met (Q-02).

### Q-09 · Secrecy indicator colour for Not verified contacts

The `SecrecyIndicator`'s forward-secret state is green (`occultaVerified`), and Sweep 4 rules out green for unverified contacts. Recommendation: for Not verified contacts, keep the label and description, drop the green, and show the trust line above it.

**Decided 2026-10-15,** as recommended.

### Q-10 · At the meeting: a wrong pick or a real mismatch?

§5 asks the user which conversation the person belongs to. A wrong pick gives a mismatch that looks like an interception. Offering "pick again" is needed, but re-picking must not become a way to dismiss a real W-11. Needs UX design.

**Resolved 2026-10-15 by the contact-first flow (§3, §5).** The user starts the exchange from the contact's details, so they pick the contact deliberately and before the meeting, and there's no picker inside the ceremony. The check runs against that one contact. If the user opens the wrong person's page, that's the same mistake as in any key exchange, not something specific to cards.

**Decided 2026-10-15: show W-11 at the exchange, require an explicit acknowledgment, and store nothing.** The question as it was put:

**What remains after a mismatch.** The warning rules say the alarm can't fade into silence, and that a contact keeps a "Card swapped" state. In §5, though, a mismatch ends with the contact verified with the real person, so the danger is in the past. A stored "Card swapped" state would also be a lasting record that this contact came through a card, which Q-07 rules out for the route kind. The options:
- **Show W-11 at the exchange, require an explicit acknowledgment, and store nothing.**
- **Keep a persistent state,** at the cost of that record.

### Q-11 · Message Ban

Secure Mode activation sends a ban bundle to contacts (`Message Ban/FINDINGS.md`). The options for a Not verified contact both cost something:
- **Send it:** reveals the activation to someone the user hasn't met.
- **Don't send it:** they stay free to message during the coercion window.

**Moved 2026-10-15: belongs to Message Ban, and doesn't block cards.** Message Ban isn't built or scheduled, and this question doesn't affect the cards' protocol or UI. It is settled in `Message Ban/FINDINGS.md`, where the open note stays.

### Q-12 · Wire shape of the first message

Where does the ML-KEM ciphertext go?
- **As an inline field** (Multi-Device D-08's sketch). The field makes the bundle distinguishable on the wire.
- **Inside a classical outer layer.** This hides it as a field. The ciphertext isn't secret, so wrapping it classically costs no post-quantum strength.

Recommendation: the outer layer. New vectors in `OccultaTests/Interop/InteropVectors.json` either way.

**Left for the SPEC (2026-10-15).** This is a wire-format detail, not a product or UI decision.

**Decided 2026-10-16 in [SPEC.md](SPEC.md) §4: the outer layer.** Card messages use the group format with one slot, and no new `Version`, `Mode` or `Recipient` field. A bootstrap slot's `wrappedPayload` is a classical AES-GCM layer holding the ML-KEM ciphertext and an inner layer under a key that mixes in the ML-KEM secret. Its visible mode is `.forwardSecret`, like any iOS 26 slot. Every bootstrap message from Carol carries her full introduction, so whichever arrives first redeems the card. Out-of-order delivery is normal here. The larger slot size isn't padded (decided 2026-10-16, SPEC §4.5): the channel has already carried the card itself.

### Q-13 · Open-card details

**Deferred 2026-10-15,** with carriers and open cards (§4). Kept for when they're built.

The two modes are decided (§4). These details are not:

- **Can a carrier pass a card on outside Occulta?** If so, the card file reaches that channel's storage and backups, so the carrier needs W-02 too. They didn't create the card, so they're less likely to weigh that.
- **How does a holder's app know a named card from an open one?** The simplest answer is a mode flag inside the signed card. That tells every holder the issuer's intent, a small disclosure, and a modified app can ignore it (§4).
- **Is there a maximum number of carriers?** Nothing technical needs one, since the card doesn't grow. But each carrier is another person who could swap it. Without a route record, a limit couldn't be counted anyway.

### Q-14 · One Not verified tier with the existing shared/transferred keys

**Decided 2026-10-15: one tier.** The app already has an amber "! UNVERIFIED" status: a key in `contactPublicKeys` whose recorded owner isn't this device's identity, which means it arrived through Settings → Import, shared or transferred from another device (`Contacts+DesignTokens.swift`, `verificationStatus`). The mocks showed it next to the card contacts' "! NOT VERIFIED" in the same amber, which is the near-identical-badges problem Q-07 rules out. Neither kind of key came from an in-person exchange on this device. So:
- Card contacts and shared/transferred keys share one tier: one "Not verified" badge, chip, section and count. The "UNVERIFIED" label goes away.
- The card warning rules apply to both. The trust line (W-06) is always visible. The existing `UnverifiedNoticeV2` hides its explanation behind a tap, which the rules forbid, so it is replaced by W-06.
- W-06's copy names no route, so it fits both.
- For an imported user who moved their contacts from an old phone, every imported contact now shows W-06 permanently. That is the existing status, made visible.

**The question raised next (closed below): do the §6 hard blocks apply to shared/transferred keys?** Today they don't. An imported key keeps its ML-KEM material, so `mlkemEligibleContacts` offers it as a vault trustee, and nothing else gates on `verificationStatus` either, apart from the identity-challenge button. Card contacts are blocked by construction (§1, §6). With one badge, two contacts that look the same would allow different things. Applying the blocks to imported keys would change behaviour for existing users: an imported contact who is already a trustee would stop being eligible. That needs a migration plan for existing shard holders before it can be decided.

**Closed 2026-10-15: no imported keys exist, and none will in the foreseeable future** (product owner). The code agrees:
- Only v1.0.0 could share a contact as a file.
- From v1.1.0 the import screen was unreachable behind `useComposableMessage`, and its last caller was removed in `d4d4bb44` (2026-03-31).
- Even then, v1.0.0 had no ML-KEM, and trustee eligibility has required ML-KEM material since shards shipped in v1.10.0. So no imported key could hold shards.

The tier therefore holds only card contacts in practice, and the §6 question has nothing to apply to. **If contact sharing ever returns**, the keys it produces join this tier with the same rules, §6's hard blocks included. A shared key is a third party asserting "this key is Bob's", which is the vouching this design rules out. Note for that case: `convertToMutableCopy` puts a contact's ML-KEM shared secrets into a `Contact.Draft`, so a share built on it would send the pairwise post-quantum secrets to a third party.

Left in the code and unreachable: `Import` (`Import+View.swift`), `ContactManager.save(contacts:)`, `VerificationStatus.unverified` and `UnverifiedNoticeV2`. When cards are built, the `.unverified` case can become the Not verified tier.

---

## Relationship to earlier plans

| Document | What it said | What this changes |
|---|---|---|
| `Friction/USER_ENGAGEMENT_FRICTION.md:284`, Sweep 4 component 1 | Multi-use contact card: long-term key + signed prekey batch, with static prekeys | Replaced by a single-use card with its own keys and no prekeys (D-05) |
| Same, component 3 (gossip audit) | Detects a first-contact swap as the graph fills in | Can't check card keys; detection waits for the meeting |
| Same, component 4 (introductions) | A verified mutual forwards both keys, signed; a product-owner call | Recast: contacts pass the issuer's card on, through any number of hops, asserting nothing and leaving no route record (D-04, §4). Allowed under D1 (Q-01) |
| Same, second open decision (D2) | Send-capable or import-only | Decided for cards 2026-10-15: send-capable (Q-02) |
| Same, H5 | Key-in-bundle rejected; warning fatigue and downgrade risk | Not key-in-bundle (D-04); the warning rules follow H5 |
| `Friction/CONSUMER_OPENING_AND_CEREMONY.md` §6–7 | Introduced and Unverified rungs; D1–D3 | Both rungs become one Not verified badge, with no route text (§4, Q-07) |
| [Remote Key Exchange/FINDINGS.md](../Remote%20Key%20Exchange/FINDINGS.md) D-06, Q-01, Q-04, Q-05 | No record of how a key arrived; two-tier claims; hard block for trustees and payment cards; introductions adjacent to vouching | The card key makes the block the default (§1, §6); Q-01 applies unchanged; Q-05 is answered here |
| [Multi-Device Contacts/FINDINGS.md](../Multi-Device%20Contacts/FINDINGS.md) D-08 | ML-KEM can be introduced asynchronously, for a future opt-in, weaker trust model | This is that feature, using D-08's mechanism |
| Same, "Rejected: self-vouching device certs"; `ROADMAP.md:140` | No trust for a new key without a UWB exchange | Kept: no trust is granted, and the identity key leaves the phone only in person |
| `Master Feature & Expansion Analysis.md:481` | Anonymous source drop omitted: shared prekeys or no forward secrecy | Cards avoid both, but aren't a public drop: a published card works once, for whoever uses it first |
| `Master Feature & Expansion Analysis.md:571`; `Feature Ideation — 2026-07-10 Community Demand Pass.md:118` | Verified introductions off-limits | Aligned 2026-10-15: carried cards are outside the ruling, which stands for verified introductions (Q-01) |
| `Master Feature & Expansion Analysis.md` #22 | Keys never travel in cleartext, so probing is limited | Preserved by the card key (§1) |
| `Prekey Continuity/DESIGN.md` §3.1, §7 | Sender signature on last-resort sealing; `SecrecyIndicator` wording rules | Pattern for the first-message signature (§3) and the warnings |
| `Docs/Bugs/v1.10.0/Non-Safe-Sender-Rejection-Is-A-Duress-Detection-Oracle.md` | No bundle rejected by depth; presence oracle documented | Constrains Q-03 |
| `Message Ban/FINDINGS.md` | Ban bundles at Secure Mode activation | Q-11 |
| `Feature Evolution & Trajectory.md`, "Noted and rejected: cross-device cert vouching" | Standing invariant against vouching-in new trust | Cards distinguished there |

---

## Recommendation

**Don't build the forwarding form** (D-03). If introductions are wanted at all, this is the shape:
- the owner issues the card;
- it works once and carries its own key;
- it is carried, not vouched for;
- the contact stays Not verified until a UWB exchange;
- the warnings above appear at every point where something can go wrong.

**Q-01, Q-03 and Q-08 are decided.** The largest engineering item is the per-contact own key in the send path (Q-08).

The direct route is also the better form of Sweep 4's contact card (D-05), with or without a carrier.

---

## Action items

**Before any protocol work:**

- ~~Answer Q-01 and align the four docs that disagree on D1.~~ Done 2026-10-15.
- ~~Answer Q-02 (D2).~~ Done 2026-10-15: send-capable.
- ~~Rule on Q-03 with the same discipline applied to `originDepth`.~~ Done 2026-10-15.
- ~~Confirm Q-08.~~ Done 2026-10-15: card key.

**If pursued:**

- ~~Write a SPEC covering:~~ Drafted 2026-10-16 as [SPEC.md](SPEC.md). Vectors are listed in its §10 and recorded with the implementation.
  - the card and first-message wire formats, with new interop vectors (Q-12);
  - the pending-card record (Q-05);
  - the receive-path order (contacts first, then pending cards);
  - the in-person linking step (§5, Q-10).
- ~~Plan stages with tests and a no-data-loss migration per stage.~~ Done 2026-10-17 as [BUILD_PLAN.md](BUILD_PLAN.md).
- ~~Tests:~~ Done 2026-10-17, in `OccultaTests/IntroductionCards/`. Each item below has a test; the two-phone and duress cases are in `CardConversationTests.swift`, the meeting cases in `CardMeetingCheckTests.swift`.
  - every gate in §6 refuses a card contact;
  - every warning renders identically at every depth;
  - an ML-KEM-key-only swap fails recognition (the §2 signature);
  - a second use of a card fails like an unopenable bundle;
  - after redemption, a message from a different sender with a different introduction fails like an unopenable bundle (§3);
  - the post-quantum secret from Carol's first message covers her later messages before Bob replies (SPEC detail);
  - a card is byte-identical after every hop, and no carrier's identity is written anywhere (§4);
  - an expired or cancelled card leaves no keys behind;
  - creating a new card for a contact cancels the old one and deletes its keys (§3);
  - discarding a card conversation deletes its keys and returns the contact to pending (§3);
  - the exchange completes on a mismatch, and the card keys are deleted on both sides (§5);
  - a hidden contact's active card is tried and redeemed at a duress depth (Q-03);
  - an expired card is refused on arrival at every depth, and cleanup leaves the row the same size (Q-03).
- ~~Update `README.md` claims in the same change that makes the feature reachable (Q-01).~~ Done 2026-10-17: the two impersonation claims are now limited to contacts verified in person, and a Features section describes cards.

---

## Known bugs

| # | Summary | Status |
|---|---|---|
| — | None filed. | — |

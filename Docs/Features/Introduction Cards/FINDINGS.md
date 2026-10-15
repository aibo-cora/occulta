# Introduction Cards — Design Findings

**Status:** Proposal. No SPEC. The carrier route is blocked on D1, a product decision (Q-01). The direct route involves no third party and is not. Both routes depend on D2 (Q-02). Not scoped for a release.
**Origin:** Design discussion, 2026-10-14. The question raised was whether a contact's *encryption* key could be vouched for, rather than their identity key, so that people we introduce can encrypt to them, marked unverified until they meet. It was assessed against the no-vouching rulings, Sweep 4's trust ladder and the shipped receive path, then reshaped into owner-issued, single-use cards.
**Relation to earlier plans:** this is a worked design for Sweep 4 components 1 and 4 (`Friction/USER_ENGAGEMENT_FRICTION.md:284`). It replaces component 1's card and recasts component 4, so the mutual contact carries a card and asserts nothing. Every earlier plan it touches is listed in [Relationship to earlier plans](#relationship-to-earlier-plans), and each one points back here.
**Decided so far (2026-10-14):** the carrier is never named on the recipient's phone (Q-07). A card may reach its recipient directly or through any number of carriers, and the issuer chooses a named or an open card when creating it (§4). Two ways of recording the route were considered and not adopted ([Considered and not adopted](#considered-and-not-adopted)). The badge design is undecided (Q-07).

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
2. Bob chooses who gets a named card, or who first carries an open one (§4), and each card works once.
3. No identity key and no name travel on the card.
4. Bob's phone accepts a stranger only if they use a card Bob made.
5. Each card carries its own one-time prekey.

Is this vouching? No third party signs or asserts anything, and no trust is granted: the contact stays Not verified until a UWB exchange. Whether that keeps the carrier route on the right side of the line is D1 (Q-01).

It is also not H5's rejected "key-in-bundle" shortcut (`USER_ENGAGEMENT_FRICTION.md:156`). No session key ever travels next to its ciphertext. And the upgrade happens only in person, so the *"reply with your real key so we can go secure"* moment, where an attacker would insert themselves, doesn't exist.

### D-05 · How this differs from Sweep 4's contact card (component 1)

| | Sweep 4 contact card | Introduction card |
|---|---|---|
| Carries | Long-term public key + signed prekey batch | Its own card key + one one-time prekey + one ML-KEM key + expiry, signed by the card key |
| Who can use it | Anyone holding it, repeatedly | The first person to use it, once |
| First-message forward secrecy | Signed-prekey level (static prekeys) | Full (one-time prekey) |
| Identity key leaves the phone | Yes | No |
| Cards linkable to each other | Yes (same long-term key) | No |
| Posting one publicly | Discouraged | Pointless: only the first user gets through |
| Component 4 (introductions) | Mutual forwards both keys, signed | Mutual carries the owner's card and asserts nothing |

Sweep 4's "known nuance" goes away. The first message doesn't fall back to signed-prekey forward secrecy, because the prekey it uses is one-time.

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
- **The nonce changes nothing.** It changes the signed message, not the key, so the key can still be recovered. A card doesn't need it to be unique either: the card key is new and the one-time prekey makes it single-use.

The in-person check (§5) already makes this link, and makes it only when they meet.

A hiding commitment instead of a signature, `SHA-256(identityPub ‖ nonce)` with the nonce revealed at the meeting, would be unlinkable but proves nothing. Alice holds Bob's identity key, so she could put the same commitment on a swapped card, and only the §5 card-key signature would catch it.

### 2. What a card contains

| Field | Why |
|---|---|
| Card key, public half (P-256, Secure Enclave) | Bob's identity in this relationship until they meet |
| One one-time prekey, public half | Forward secrecy for the first message, and what makes the card single-use |
| One ML-KEM-1024 encapsulation key (iOS 26+) | Post-quantum protection from the first message (`Multi-Device Contacts/FINDINGS.md` D-08) |
| Expiry | Limits how long a lost or intercepted card stays usable |
| Card key's signature over all of the above, with its own domain-separation prefix | Without it, a carrier could swap just the prekey. They'd read the first message and re-seal it to Bob's real prekey, and the in-person check (§5) would still pass, because the card keys match |

**A card contains no name, no photo, no identity key, and nothing that names the carrier.** Carol learns who it's from through the route it arrived by.

### 3. How a card is used

1. **Bob creates a card** and labels it for himself, e.g. "for Carol". The label is his own text, on his phone only. It is stored as a pending card: an encrypted, fixed-size record. It holds the label and the private halves of the card key, prekey and ML-KEM key, as Enclave blobs (as prekeys are held under Prekey Continuity D9).
2. **Bob delivers it**, himself or through one or more carriers (§4).
3. **Carol imports it.** A Not verified contact appears, and Carol names it.
4. **Carol sends a first message.** It is sealed in forward-secret mode to the card's prekey, with ML-KEM encapsulated to the card's key. The payload carries Carol's own new card key, a prekey batch and an ML-KEM encapsulation key, all signed with her card key. That signature plays the role the sender's ephemeral signature plays for last-resort sealing in groups (`Prekey Continuity/DESIGN.md` §3.1). Without it, anyone holding the card could claim any card key, and §5 couldn't tell who wrote the first message.
5. **Bob's phone recognises it.** When `identifyOwner` matches no contact, the receive path tries Bob's pending cards before failing. The number of pending cards is capped, so this is cheap. If a card opens, its prekey is consumed and the pending card removed, following the rule that a prekey is consumed as soon as it opens a bundle (`SECURITY_CHECKLIST.md` §2). A Not verified contact appears under Bob's label.
6. **Bob replies.** He uses Carol's prekeys and encapsulates to her ML-KEM key. After these two messages the pair holds two ML-KEM secrets, as after a ceremony, and forward secrecy works per contact as it does for verified contacts.
7. **They meet** (§5). Alternatively the card expires or Bob cancels it, and the pending record and its keys are deleted.

### 4. Delivery routes

| | Through carriers (Alice, and anyone after her) | Shared directly by Bob |
|---|---|---|
| Who could swap the card | Any carrier on the route, or someone holding one of their unlocked phones | Anyone controlling the channel: the messaging app, the email account, a phone or cloud backup |
| Where the card file ends up | Inside Occulta bundles, unless a carrier shares it outside Occulta (Q-13) | The other app's storage and its cloud backups |
| Third party involved | Yes, so gated on D1 | No |
| Best for | Someone Bob can't reach privately, or doesn't know yet | In person, or a channel Bob already trusts |

**Through carriers.** Bob sends the card to Alice inside an ordinary bundle. Whoever holds the card can use it or pass it on. Each holder's copy is deleted when they pass it on.

**The card is identical at every hop.** It's signed by Bob's card key, so a carrier can't add to it without breaking the signature. Nothing in it records who carried it or how many people did. Anyone holding a copy, at any point on the route, sees the same bytes.

**Named and open cards (decided 2026-10-14).** Bob chooses one when he creates the card:

- **Named:** meant for one person. Bob hands it over himself, or asks a carrier to give it to that person. Bob chooses the recipient.
- **Open:** for whoever the carriers think should be able to reach Bob. Bob chooses only the first carrier, and the recipient is decided by people he may not know. Single use and the cap on pending cards (Q-05) still limit how many strangers can reach him at once.

What this costs, stated plainly:

- **Every carrier is someone who can swap the card.** The more carriers on the route, the more people the recipient's trust rests on, and none of them can be identified afterwards.
- **For an open card, the recipient knows whose card it is only from what the person who gave it said,** and that may itself be second-hand. A card carries no name, so the owner's identity is relayed by word of mouth at every hop until the in-person check.
- **The mode guides honest apps; it can't be enforced.** A modified app can pass on a named card. Single use is the real limit.

**Badge design is undecided (Q-07).** The earlier recommendation was one badge for every route, with the route shown as text. With two near-identical badges, the stronger one starts to read as safe, and users can't weigh carrier risk against channel risk anyway. `CONSUMER_OPENING_AND_CEREMONY.md` D3 argues the opposite for two in-person rungs, but those differ in how rigorous the user's own check was. These routes differ only in who could have swapped the card, and the user did no check on any of them.

### 5. Meeting in person: linking the conversation

The UWB ceremony runs unchanged, plus one step:

1. Each app asks whether the person in front of them is one of their Not verified contacts ("Is this Carol (card)?").
2. If both people answer yes, each side signs the ceremony transcript with its card key.
3. Each side checks that signature against the card key it holds for the other.

- **Match.** The conversation merges into the verified contact, and the card keys are deleted on both sides. The app can truthfully say every earlier message in that conversation went to this person:
  - Carol's card key signed her first message (§3 step 4).
  - Bob's card key signed the prekey Carol sealed to (§2).
  - Everything after that used prekeys exchanged inside those authenticated messages.
- **Mismatch.** An alarm names the conversation that was intercepted (W-11). The conversation is not merged.

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

The cipher suite matches verified contacts, so Sweep 4's invariant *"identical cipher suite at every rung"* holds, except on iOS 18.6–25 (Q-06).

---

## Warnings: what can go wrong, said where it can go wrong

### Rules

These carry over from earlier decisions:

- **Always shown, never behind a tap, never a dismissible dialog.** From Sweep 4: *"warning fatigue is the primary failure mode … a persistent per-contact badge visible in the contact list, at compose, and at send — never a one-time dialog."* H5 adds that click-through warnings *"train users out of reading the app's security signals."* The working model is the compose `SecrecyIndicator` (`Prekey Continuity/DESIGN.md` §7): a label and a description, always visible.
- **Name the failure and the action.** Each warning says what could happen ("someone else could read these messages") and what to do ("verify in person before sending anything sensitive"). Never use "secure", "safe", "anonymous", shields or checkmarks.
- **Claim no more than the design delivers** (`Docs/Audit/OPEN_LIMITATIONS.md` §E).
- **Same text at every depth.** Text depends only on the contact's or card's own state, never on the current depth (`Prekey Continuity/DESIGN.md` §7).
- **Secrecy and trust are separate lines.** A Not verified contact's next message can be forward-secret. The `SecrecyIndicator` green is the `occultaVerified` token, and Sweep 4 rules that *"nothing about an unverified contact may render green or 'secure'"*. So for a Not verified contact, the trust line comes first and the secrecy state isn't green (Q-09).
- **The alarm can't fade into silence.** After W-11, the contact keeps a "Card swapped" state until it's deleted.

### Draft copy

Placeholders:
- `{Name}` is the user's own label for the contact.
- `{route}` is "passed on by a contact" or "opened from a file". The carrier is never named (Q-07). Whether the route is shown at all depends on the badge design, which is undecided.

| # | Where | What can go wrong | Draft copy |
|---|---|---|---|
| W-01 | Creating a named card (issuer) | Whoever uses the card first becomes "{Name}" to you | "Anyone who gets this card before {Name} can use it and pretend to be them. Give it only to {Name}, or to someone you'd trust to introduce you. It works once and stops working on {date}." |
| W-02 | Sharing it directly, before the share sheet (issuer) | The channel keeps a copy, and whoever controls it can use the card first | "The app you send this through may keep a copy, including in its backups. Anyone who can read that chat could use the card before {Name} does. Once the card is used or expired, a leftover copy is useless." |
| W-03 | Asking a contact to pass a named card on (issuer) | The carrier gives {Name} a different card | "{Carrier} will be able to see this card and could give {Name} a different one. Only ask someone you'd trust to introduce you in person." |
| W-04 | Receiving a card from its issuer to pass on (first carrier) | It goes to the wrong person | "{Sender} asked you to pass this card on. Whoever you give it to can message {Sender} once. It is removed from your phone when you pass it on." |
| W-05 | Importing a card (recipient) | The card was swapped on the way, or isn't whose you were told | "Not verified. You know whose card this is only from what the person who gave it to you said. If it was swapped on its way to you, your messages will go to whoever swapped it, and they'll be able to read them. Meet {Name} and verify in person before you send anything you wouldn't want a stranger to read." |
| W-06 | Contact list, contact screen, compose, send (both); persistent | Same as W-05 | Badge: "Not verified · {route}". Description: "You haven't verified this contact in person. If the card was swapped, someone else is reading this conversation." |
| W-07 | After the first send (recipient) | Someone used the card first, so no reply will come | "Waiting for the first reply. If none comes, someone may have used this card before you. Ask {Name} for a new one, in person or through someone you trust." |
| W-08 | First message arrives (issuer) | Whoever used the card first wrote it | "First message on your card '{label}'. Whoever used the card first wrote it. That's probably {Name}, but you can't be sure until you verify in person." |
| W-09 | Pending cards list (issuer) | A lost card can be used until it expires | "Not used yet. Anyone who has this card can use it until {date}. Cancel it if it might have reached the wrong person." |
| W-10 | A blocked feature (both) | — | "{Feature} needs a contact you've verified in person, because it relies on knowing this key belongs to them. Meet {Name} to verify." |
| W-11 | Mismatch at the in-person check (both) | The conversation was intercepted | "This isn't the person you were messaging as '{Name}'. Someone swapped the card on its way and could read everything in that conversation. Don't send anything more to that contact." |
| W-12 | Match at the in-person check (both) | — | "Verified in person. Your earlier messages with {Name} went to this person." |
| W-13 | Creating an open card (issuer) | The card goes to people you don't know, and any of them can swap it | "This card can be passed on by {Carrier} and by anyone they give it to. You won't know who ends up with it, and any of them could use it or swap it. It works once and stops working on {date}." |
| W-14 | Receiving a card from a contact who isn't its issuer (holder) | The holder can't tell whose card it is | "This card was passed on to you. You know whose it is only from what you were told. You can use it yourself or pass it on. Whoever uses it can message its owner once." The carrier isn't named (Q-07); the message it arrived in shows its sender as any message does. |

W-01 and W-03 also counter H5's downgrade point: *"attackers don't break crypto — they social-engineer victims into the weak mode."* The weak mode here is a card. An attacker posing as someone can ask the user for one, so the moment the user creates a card is where the risk is stated.

---

## Guarantees and limits

**Guaranteed, if built as above:**

- No general way in. Only someone using a card Bob made can start a conversation with him.
- Bob chooses who gets a named card, and who first carries an open one. A card works once and expires.
- Nothing records the route. The card is identical at every hop, and no carrier's identity is written anywhere.
- Forward secrecy for the first message, and hybrid post-quantum protection on iOS 26+.
- Carriers and channels never see message content.
- Bob's identity key never leaves his phone except in person.

**Limits.** These are inherent or open; none is accepted.

- **A coerced or dishonest carrier can substitute a card.** Every kind of introduction has this problem, and no design closes it. Only the in-person check (§5) detects it. No mutual contact holds the card key, so gossip (Sweep 4 component 3) and `#22` corroboration can't check it earlier. That is a direct cost of §1.
- **Whoever uses the card first wins.** Until they meet, the first message proves only that whoever used the card first sent it. Someone who uses an intercepted card becomes "{Name}". The real recipient's message then fails like any bundle that can't be opened, and the only sign is W-07. Anyone holding an unused card can also use it up.
- **Verification doesn't undo exposure.** Messages sent before a mismatch was found were readable.
- **Cards become what attackers ask for** (H5's downgrade point). Mitigated by W-01 and by the permanent badge. Not closed.
- **More carriers, more people who can swap.** Each carrier on an open card's route is someone the recipient's trust rests on, and none can be identified afterwards (§4).
- **Whose card it is travels by word of mouth.** A card carries no name. The recipient believes it's Bob's because the person who gave it said so, and on an open card that may be second-hand.
- **Named versus open can't be enforced.** A modified app can pass on a named card. Single use is the only hard limit.
- **No help for people who aren't on Occulta.**

---

## Forensic and coercion review

| Observer | What they learn |
|---|---|
| Finds a card file (another app's backup, a Files folder) | Three public keys, an expiry and a signature. No name and no identity key. Whether the file reveals Occulta is Q-04. An unused, unexpired card can be used once. |
| Seizes the recipient's phone | A Not verified contact under a card key, with only the route kind. It can't be connected to the issuer's identity key or to other cards. The seizer can message the issuer as that contact, as with any contact on a seized phone. |
| Seizes two phones holding cards from the same issuer | Two unrelated keys. Verified contacts all hold one identity key, so cards are less linkable than verified contacts. |
| Seizes a carrier's phone | Nothing of the card once it was passed on. With the phone unlocked, they can give the carrier's contacts fake cards. That reach is limited to that contact list, and each fake is caught at its in-person check. |
| Holds a copy of a card anywhere on its route | The same bytes at every hop. Nothing shows who carried it or how many people did. |
| Images the issuer's phone | Pending cards are encrypted, fixed-size rows. Their number is visible unless slots are preallocated (Q-05). |
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

### Q-01 · D1: does the carrier route cross the no-vouching line? (blocking, product decision)

The docs currently disagree on D1:
- **Open:** `USER_ENGAGEMENT_FRICTION.md` (Sweep 4 item 4) and `CONSUMER_OPENING_AND_CEREMONY.md` §7.
- **Off-limits:** `Master Feature & Expansion Analysis.md:571` and `Feature Ideation — 2026-07-10 Community Demand Pass.md:118` say "re-affirmed as off-limits".

Those last two entries describe verified introductions, where a mutual contact vouches. The carrier route here asserts nothing and grants nothing (D-04). Decide, then align all four docs.

`Remote Key Exchange/FINDINGS.md` Q-01 applies here unchanged: a Not verified tier makes public claims such as *"No one can impersonate you remotely"* (`README.md:15`) conditional on the contact's tier. That has to be settled before shipping, not after.

### Q-02 · D2: send-capable or import-only?

This design assumes send-capable, with W-05 and W-06 carrying the risk. Import-only would require a remote SAS (the Confirmed rung, `Remote Key Exchange/FINDINGS.md`) before the first send. That removes the first-contact swap risk but loses the asynchronous first message. Still open.

### Q-03 · Duress (open, needs a decision)

The shipped rule says no bundle is rejected because of the current depth, and an unrecognised sender fails the same way at every depth (`Docs/Bugs/v1.10.0/Non-Safe-Sender-Rejection-Is-A-Duress-Detection-Oracle.md`, final design 2026-08-08). Applied to cards:

- Creating a card at a duress depth must work, and the card belongs to that depth (floor semantics, as `originDepth`).
- Redemption must try every pending card regardless of depth, just as `identifyOwner` matches hidden contacts. Otherwise a coercer holding an unused card learns from a failure that the card came from another depth.
- That puts a card redeemed from a hidden depth into the presence-oracle shape recorded 2026-08-13: a message opens from someone absent from the list. Should cards inherit that documented limitation, or behave differently?
- Pending cards stay invisible at depths that didn't create them.

### Q-04 · Can a card file be unrecognisable?

A card shared directly ends up in another app's storage. If it starts with an Occulta marker, it's the "I use Occulta" evidence that Sweep 4 and `Remote Key Exchange/FINDINGS.md` D-08 warn about. Can a card look like random bytes and still be importable? For example, the app could recognise it by trying it, the way the receive path tries pending cards.

### Q-05 · Pending-card storage

The cap and the expiry are product choices; 8 cards and 14 days are placeholders. The row count is visible on disk. Preallocated fixed slots would hide it, which is the same question the soft-delete cap answers for contacts.

### Q-06 · iOS 18.6–25

These versions have no ML-KEM, so cards to or from them are classical-only. Options:
- Allow it, with the post-quantum status the secrecy indicator gains in v2.0.0 step 7.
- Require iOS 26 at both ends.

### Q-07 · Should the carrier be named on the recipient's phone?

"Card via Alice" helps the user judge trust, but on a seized phone it's a recorded introduction. Recommendation: store only the route kind. The user can add the carrier to the contact's notes if they choose.

**Decided 2026-10-14: the carrier is never named on the recipient's phone,** in the badge, the warnings or the stored record. C-01 and C-02 record two ways of recording the carrier that were considered and not adopted.

**Still open: the badge design,** including whether the route kind ("passed on by a contact" / "opened from a file") is shown at all, and whether every route shares one badge (§4).

### Q-08 · Card key or identity key on the card? (confirm §1)

This is the trade in §1. Recommendation: card key. It keeps the trust graph's meaning, cards unlinkable, and `#22`'s premise intact. It costs per-contact own keys throughout the send path, and the chance to catch a swapped card before meeting.

### Q-09 · Secrecy indicator colour for Not verified contacts

The `SecrecyIndicator`'s forward-secret state is green (`occultaVerified`), and Sweep 4 rules out green for unverified contacts. Recommendation: for Not verified contacts, keep the label and description, drop the green, and show the trust line above it.

### Q-10 · At the meeting: a wrong pick or a real mismatch?

§5 asks the user which conversation the person belongs to. A wrong pick gives a mismatch that looks like an interception. Offering "pick again" is needed, but re-picking must not become a way to dismiss a real W-11. Needs UX design.

### Q-11 · Message Ban

Secure Mode activation sends a ban bundle to contacts (`Message Ban/FINDINGS.md`). The options for a Not verified contact both cost something:
- **Send it:** reveals the activation to someone the user hasn't met.
- **Don't send it:** they stay free to message during the coercion window.

### Q-12 · Wire shape of the first message

Where does the ML-KEM ciphertext go?
- **As an inline field** (Multi-Device D-08's sketch). The field makes the bundle distinguishable on the wire.
- **Inside a classical outer layer.** This hides it as a field. The ciphertext isn't secret, so wrapping it classically costs no post-quantum strength.

Recommendation: the outer layer. New vectors in `OccultaTests/Interop/InteropVectors.json` either way.

### Q-13 · Open-card details

The two modes are decided (§4). These details are not:

- **Can a carrier pass a card on outside Occulta?** If so, the card file reaches that channel's storage and backups, so the carrier needs W-02 too. They didn't create the card, so they're less likely to weigh that.
- **How does a holder's app know a named card from an open one?** The simplest answer is a mode flag inside the signed card. That tells every holder the issuer's intent, a small disclosure, and a modified app can ignore it (§4).
- **Is there a maximum number of carriers?** Nothing technical needs one, since the card doesn't grow. But each carrier is another person who could swap it. Without a route record, a limit couldn't be counted anyway.

---

## Relationship to earlier plans

| Document | What it said | What this changes |
|---|---|---|
| `Friction/USER_ENGAGEMENT_FRICTION.md:284`, Sweep 4 component 1 | Multi-use contact card: long-term key + signed prekey batch, with static prekeys | Replaced by a single-use card with its own key and a one-time prekey (D-05) |
| Same, component 3 (gossip audit) | Detects a first-contact swap as the graph fills in | Can't check card keys; detection waits for the meeting |
| Same, component 4 (introductions) | A verified mutual forwards both keys, signed; a product-owner call | Recast: contacts pass the issuer's card on, through any number of hops, asserting nothing and leaving no route record (D-04, §4). Still D1 (Q-01) |
| Same, second open decision (D2) | Send-capable or import-only | Still open (Q-02); this design assumes send-capable |
| Same, H5 | Key-in-bundle rejected; warning fatigue and downgrade risk | Not key-in-bundle (D-04); the warning rules follow H5 |
| `Friction/CONSUMER_OPENING_AND_CEREMONY.md` §6–7 | Introduced and Unverified rungs; D1–D3 | Both rungs become one Not verified badge, with the route as text (§4) |
| [Remote Key Exchange/FINDINGS.md](../Remote%20Key%20Exchange/FINDINGS.md) D-06, Q-01, Q-04, Q-05 | No record of how a key arrived; two-tier claims; hard block for trustees and payment cards; introductions adjacent to vouching | The card key makes the block the default (§1, §6); Q-01 applies unchanged; Q-05 is answered here |
| [Multi-Device Contacts/FINDINGS.md](../Multi-Device%20Contacts/FINDINGS.md) D-08 | ML-KEM can be introduced asynchronously, for a future opt-in, weaker trust model | This is that feature, using D-08's mechanism |
| Same, "Rejected: self-vouching device certs"; `ROADMAP.md:140` | No trust for a new key without a UWB exchange | Kept: no trust is granted, and the identity key leaves the phone only in person |
| `Master Feature & Expansion Analysis.md:481` | Anonymous source drop omitted: shared prekeys or no forward secrecy | Cards avoid both, but aren't a public drop: a published card works once, for whoever uses it first |
| `Master Feature & Expansion Analysis.md:571`; `Feature Ideation — 2026-07-10 Community Demand Pass.md:118` | Verified introductions off-limits | Disagrees with the friction docs; this isn't a verified introduction (Q-01) |
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

**Decide Q-01 first.** It's a product call, and the docs currently disagree. Then decide Q-03 (duress) and Q-08 (card key), which settle most of the engineering.

**If Q-01 answers no, the direct route still stands.** It involves no third party. It is also the better form of Sweep 4's contact card (D-05), with or without a carrier.

---

## Action items

**Before any protocol work:**

- Answer Q-01 and align the four docs that disagree on D1.
- Answer Q-02 (D2).
- Rule on Q-03 with the same discipline applied to `originDepth`.
- Confirm Q-08.

**If pursued:**

- Write a SPEC covering:
  - the card and first-message wire formats, with new interop vectors (Q-12);
  - the pending-card record (Q-05);
  - the receive-path order (contacts first, then pending cards);
  - the in-person linking step (§5, Q-10).
- Plan stages with tests and a no-data-loss migration per stage. The new records are additive and no existing row changes, but the per-contact own-key change (Q-08) touches every send path.
- Tests:
  - every gate in §6 refuses a card contact;
  - every warning renders identically at every depth;
  - a prekey-only swap fails §5 (the §2 signature);
  - a second use of a card fails like an unopenable bundle;
  - a card is byte-identical after every hop, and no carrier's identity is written anywhere (§4);
  - an expired or cancelled card leaves no keys behind.
- Update `README.md` claims in the same change that makes the feature reachable (Q-01).

---

## Known bugs

| # | Summary | Status |
|---|---|---|
| — | None filed. | — |

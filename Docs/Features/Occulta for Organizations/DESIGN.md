# Occulta for Organizations — Design

**Status:** Proposed, 2026-10-10. Not scheduled for a release. No SPEC.md yet. **The trust model stays as it
is** (D1, decided 2026-10-10): every key a client trusts is received in person, and no key vouches for
another. Everything else that needs a decision is listed in §8 and marked where it comes up.

An external review brief carries the same design, with the market and regulatory context this document leaves
out: [Occulta for Organizations — Design Review Brief](https://claude.ai/artifact/YUbKxoFoHqmEueigWUqdju).

**Related:**
- `Docs/Features/Organizational Identity Graph/FINDINGS.md` — organizational *identity*: employees proving
  who they are. A different feature, but its F-01, D-05 and D-06 are the precedent for rejecting a root key
  here (§4.1).
- `Docs/Features/Multi-Device Contacts/FINDINGS.md` — where the no-vouching rule was set, for a user's own
  second device.
- `Docs/Features/Prekey Continuity/DESIGN.md` — §3.1 (last-resort prekey, stage 2, v2.0.0) and §3.2 (seeding
  at the exchange, stage 5, deferred out of v2.0.0). This design needs both (§5).
- `Docs/Features/Group Messaging/SPEC.md` — per-recipient wrapping, reused for role keys.
- `Docs/Features/Crypto/bundle.md` — the bundle modes.
- `Docs/Bugs/v1.10.0/Non-Safe-Sender-Rejection-Is-A-Duress-Detection-Oracle.md` — the presence oracle
  accepted on 2026-08-13 for person contacts. §6 asks whether that acceptance extends to organizations.

---

## 1. Problem

An organization such as a hospital, clinic or law firm wants to send its clients encrypted files over channels
it already uses, and receive encrypted files back. It wants this without a portal account for the client and
without a server run by Occulta. "Client" below means whoever the organization serves; in the hospital example,
a patient.

The original proposal (2026-10-10):

1. Each organization server generates a key pair and gives its public key to a desktop app at the front desk.
2. The desktop app generates its own key pair.
3. At the desk, the client's iPhone and the desktop app exchange keys. The desktop sends its own key and every
   server's key; the iPhone sends the client's key, which the desktop forwards to each server.
4. To send, the iPhone wraps a per-message key for the desktop, one server or all of them.
5. The organization encrypts to the client's key from any terminal or server and delivers the `.occ` bundle
   over any channel.

Step 3 already kept the trust model, since every key the client trusted was handed over at the desk. Its
problems were operational: keys tied to machines, and no way to rotate them (§4.2). A first revision added an
organization root key that signs every other key. That fixed rotation but broke the trust model, and is
rejected in §4.1.

## 2. Goals and non-goals

**Goals**
- Every key a client trusts is received in person, at the organization's desk. No key vouches for another.
- Occulta, the company, runs no servers and never holds keys or client data.
- Nothing on the client's phone marks a contact as an organization, so Secure Mode can hide it like any other.
- No private key that clients trust sits in software on a shared desk computer.

**Non-goals**
- Protecting the organization's records system. The hospital keeps plaintext there, as the law requires.
- Hiding the relationship from the delivery channel (§6).
- Remote enrollment. Android.

---

## 3. Design

**The trust rule.** For a person, the party you meet is their phone. For an organization it is the front desk:
every key the client trusts comes from there, checked against a phrase the organization prints. A signature may
withdraw trust but never grant it. This is the same line `Multi-Device Contacts/FINDINGS.md` draws for a
user's own devices, where signed self-revocation is allowed and vouching-in is not.

### 3.1 Keys

- **One key per role, plus a spare.** For example Care team, Lab and Billing, and a spare kept offline. Each
  role has the same key material as a contact today: a P-256 identity key and ML-KEM-1024. Roles, not
  machines, so scope follows who should read rather than where software runs.
- **Custody.** An HSM in a multi-desk deployment, where desk computers hold no private keys and only relay
  public ones. At a single-desk practice, the Mac's Secure Enclave, with the spare on a second Mac kept offline.
  HSM requirements, ML-KEM-1024 above all, are open (D7).
- **The printed key phrase.** A hash over the whole set's public keys, rendered in the EFF wordlist the
  exchange words already use (`Passphrase+Manager.swift`). It is printed at the desk and on the
  organization's letterhead. Unlike the exchange words, which an attacker would have to match live, it is a
  fixed target that can be ground against offline, so it needs about 8 words, roughly 103 bits (D8). It
  changes when the set changes, and is reprinted then.

### 3.2 Registration at the desk

1. The client's iPhone scans a QR code on the desk screen to start the exchange. No Mac has UWB; whether a QR
   code at a staffed desk is enough is D2.
2. The desk sends the public keys of every role and of the spare, with a prekey batch and a last-resort prekey
   for each role. The iPhone sends the client's identity key and a prekey batch with a last-resort prekey.
   Each batch is signed by the identity key it belongs to, as Prekey Continuity §3.2 already requires.
3. The client checks that the phrase on the phone matches the printed one, and confirms. The phone stores
   each role as an ordinary contact (D3).
4. The desk forwards the client's key and batch to the records system, which files the key against the
   client's record.
5. **The welcome round trip.** The records system, not the desk computer, seals a welcome bundle to the key it
   now has on file and sends it over the email or messaging channel on file. The client opens it before
   leaving the desk. If it doesn't arrive or won't open, the record holds the wrong key: staff run the
   registration again, and every attempt is logged.

Step 3 stops a compromised desk computer from handing over fake organization keys. Step 5 stops it from filing
a wrong client key: an attacker's key on file means the client's phone can't open the welcome bundle. Neither
step stops an insider who controls both the desk and the records system (§6).

### 3.3 Sending and receiving

- **Organization to client.** One sending service per organization holds the client's prekey batch and calls
  the HSM, so no prekey is ever used twice. Bundles go out in group format, which last-resort keys require
  (Prekey Continuity §3.1). Results are sealed to the client's one-time prekeys and then to their last-resort
  prekey, which stays in use until the client replies (D5).
- **Client to organization.** The client picks a role and encrypts to it, using the organization's prekeys.
  Every bundle from the organization carries a fresh batch, so the client rarely runs short.

### 3.4 Rotation, loss and revocation

- **Rotation happens in person.** A new key reaches the client at their next visit. The old and new keys
  overlap until then, and the organization sends with whichever one the client holds.
- **Losing a key holder.** If the HSM or the desk Mac is lost, the spare takes over; every client already
  holds it. If the sending service lost the clients' prekey batches too, the first bundle from the spare to
  each client goes out in long-term mode, until that client replies.
- **Revocation.** Any key in the set may sign a revocation of itself or of another key received in the same
  exchange. It travels as an ordinary bundle. A revocation only removes trust, so a stolen key can't use it to
  add one; the worst it can do is revoke the whole set, which is denial of service, not disclosure. Anyone who
  controls the client's channel can block delivery of a revocation (D6).
- **A lost phone.** The client registers again at the desk. The records system replaces the old key on file.

---

## 4. Alternatives

### 4.1 An organization root key — rejected 2026-10-10

Clients pin one root key, kept offline in an HSM, which signs short-lived terminal, server and role keys.
Signed revocation lists travel inside bundles.

- **It grants trust by signature.** Clients would trust keys they never received, which is the vouching the
  trust model refuses everywhere else. `Organizational Identity Graph/FINDINGS.md` D-06 refused delegation for
  the same reason.
- **It puts the whole organization on one key.** `Organizational Identity Graph/FINDINGS.md` F-01 found that a
  single root needs a K-of-N roster (D-05) before it is safe. That would be its own design pass.
- **What it bought** was rotation and new departments without a visit. §3.4 accepts that cost instead.

### 4.2 One key per server — superseded

The original proposal (§1). Its in-person handover is kept. Two problems with it: clients would choose
"server 3", so scope followed infrastructure, and every server replaced or department added would force
clients to register again.

### 4.3 An enrollment record signed by the client's key — rejected

Proposed with §4.1 against the insider key swap: the client's app signs (hash of the record number, root
fingerprint, client key, timestamp), and servers accept only signed records.

- It proves possession of the enrolled key, not that the key is the client's. An attacker's phone signs an
  equally valid record pairing the attacker's key with the client's record number.
- Record numbers are short enough to enumerate, so the hash hides nothing.
- Storing it on the phone leaves an artifact tying the phone to the organization.

The welcome round trip (§3.2 step 5) replaces it.

### 4.4 A UWB accessory at the desk — open (D2)

iOS Nearby Interaction supports third-party UWB accessories, so a desk could range the phone the way two
iPhones do. At a staffed desk the threat is the desk computer, not a remote relay, and the accessory is driven
by that same computer, so it adds little over a QR code and the printed phrase. The standing rule names a UWB
exchange, though, so dropping it is the owner's call.

---

## 5. Dependencies

- **Prekey Continuity stage 2** (last-resort prekey, v2.0.0): needed for one-way delivery.
- **Prekey Continuity stage 5** (seeding at the exchange, deferred out of v2.0.0): required here. Without it,
  the first result to every client goes out in long-term mode, and a stolen role key, together with the
  organization's stored contact records, would open those results later.
- **A desk exchange.** A new exchange variant: QR-started, several keys from one side, a printed phrase in
  place of words compared on two screens.
- **Contact storage.** If each role is an ordinary contact (D3), the record format doesn't change. Revocation
  of a sibling key still needs each contact to record which exchange it came from, inside its sealed record.
- **A desktop app.** macOS first. A Windows app later, which relays public keys and so needs no key custody.
- **An HSM** with P-256 ECDH and ML-KEM-1024 (D7).

## 6. Forensic and coercion review

- **On the phone.** No certificates, enrollment records, record numbers or revocation lists: what §4.1 and
  §4.3 would have stored is gone. What remains is the organization's roles as contacts. Whether they can be
  told apart from person contacts at rest is D3.
- **The delivery channel.** An email from a sexual-health clinic with a `.occ` attachment discloses the
  relationship before Occulta runs. A neutral sender name narrows this but doesn't remove it. The same
  reasoning closed the 2026-08-13 decision for person contacts.
- **The presence oracle.** Accepted on 2026-08-13 for person contacts: a bundle opened at a duress depth shows
  the sender's real name while the sender is missing from the contact list. Organizations send unprompted,
  often, and what they send is sensitive. A bundle arriving during a coercion window is both likelier and
  costlier than it is between two people. **Open, needs a decision:** whether that acceptance extends to
  organization contacts (D4).
- **One-way delivery.** Every result after the desk batch is sealed to the client's last-resort prekey and
  stays openable on the phone until the client replies. **Open, needs a decision** (D5).
- **The single-desk insider.** At a single-desk practice the desk and the records system are one machine, so
  §3.2 step 5 confirms only the exchange, not the person running it. **Open, needs a decision** (D9).
- **A compromised organization key.** Whoever can use a role's keys can read what clients send to that role
  while that access lasts. With stage 5 in place, nothing goes out in long-term mode except after a lost key
  holder (§3.4), so taking a key does not open past results.

## 7. Tests and migration

Not staged yet. When it is, each stage ships with its tests and, where it touches existing data, a migration
checked for data loss. Organization contacts are new records, so the only existing data in reach is the
contact record itself: the field recording which exchange a contact came from (§5). Enclave-backed tests use
`.enabled(if: secureEnclaveAvailable())`; the desk exchange needs two physical devices, and no available
phone is free of real data, so end-to-end testing needs a test phone first.

## 8. Open decisions

| # | Decision | Where |
|---|---|---|
| D1 | Keep Occulta's trust model; no organization root key. **Decided 2026-10-10** | §3, §4.1 |
| D2 | Is a QR code plus the printed phrase enough at a staffed desk, or must the exchange use UWB through an accessory? **Open, needs a decision** | §3.2, §4.4 |
| D3 | Store each role as an ordinary contact (proposed), so an organization looks like several person contacts at rest and the record format doesn't change. **Open** | §3.2, §6 |
| D4 | Does the 2026-08-13 presence-oracle acceptance extend to organization contacts? **Open, needs a decision** | §6 |
| D5 | One-way delivery leaves results openable under the client's last-resort prekey until the client replies. Ask clients for a periodic reply, and how often? **Open, needs a decision** | §3.3, §6 |
| D6 | A revocation bundle can be blocked by whoever controls the client's channel. Add an expiry set at the desk? **Open** | §3.4 |
| D7 | What to require of the HSM, ML-KEM-1024 support above all. **Open** | §3.1 |
| D8 | Printed phrase length: about 8 words (roughly 103 bits) proposed. **Open** | §3.1 |
| D9 | The single-desk insider. **Open, needs a decision** | §6 |

## 9. Known bugs

| # | Summary | Status |
|---|---|---|
| — | None filed; nothing is built | — |

# Message Ban — Design Findings

**Status:** Proposed, adopted in principle 2026-08-28. Not implemented, not scoped for a release.
**Context:** Design discussion, 2026-08-28. Extracted from
`Docs/Bugs/v1.10.0/Non-Safe-Sender-Rejection-Is-A-Duress-Detection-Oracle.md`, which retains the
decision this feature responds to and the record of four objections raised against it and withdrawn.
**Companion:** [Do Not Disturb](../Do%20Not%20Disturb/FINDINGS.md) — the unilateral fallback covering
what a ban cannot reach. The two are complements, not alternatives.

---

## Read this first

The leak this feature mitigates is **an accepted, documented limitation, not an open bug.**

At a duress depth, an inbound bundle from a contact hidden at that depth opens and renders with the
sender's name. That was traced end to end on 2026-08-13, evaluated against five possible handlings,
and closed deliberately: the flow is left exactly as it is. It has since been re-filed as a
High-severity defect twice — Bugs 103 and 104 — by tracing the inbound path without reading that
decision, and both are closed as duplicates.

**Do not file it again, and do not "fix" it by gating the render or rejecting the bundle.** Both are
rejected options with recorded reasoning. This feature exists precisely because the render itself
cannot be fixed: it attacks the precondition instead.

## What it is

Every option in the 2026-08-13 table handles a hidden contact's message *after* it arrives. This one
attacks the precondition: **if sensitive contacts do not send during the coercion window, the
residual never fires.** It is the first proposal against that residual that is not a variation on
hiding something at render time.

### Flow

1. The user believes coercion is possible and activates Secure Mode.
2. At the end of activation the app presents a crafted bundle, encrypted per contact, carrying a
   message-ban directive.
3. The user sends it through a transport channel of their choosing.
4. Recipients open what reads as an ordinary message — *"Please don't disturb me until further
   notice"* — which carries the ban. The recipient's app offers its own Secure Mode **setup flow**
   (their PINs, their choices — not remote execution), marks the sender sensitive, and optionally
   offers other contacts.
5. The ban lifts. See "Lifting" below — an explicit bundle is the last resort, not the default.

Enforcement is on the recipient's device: their app declines to encrypt to the issuer until lifted.

## Design requirements

**1. Addressed to all contacts, not a selected subset.** A selective recipient set is published in
cleartext by the transport — the delivery app shows which 7 of 40 people received it — and "why those
seven" has no good answer under coercion. All-contacts addressing also *explains* the silence it
creates: "why is nobody messaging you?" / "I asked them not to" is better cover than unexplained
quiet.

**2. Stateless on the issuer.** Local ban state buys only a UI affordance and costs a new field
needing per-depth padding, constant array length, `UInt8` encoding and unconditional creation — all to
conceal a fact with no operational use. Store nothing. Nothing stored is nothing to gate and nothing
to neutralise.

**3. Generic privacy wording in the recipient prompt, never coercion framing.** The justification
shown for the setup flow is the only place this design can leak into a human, and the leak is
entirely avoidable. *"Alice has asked not to be disturbed — set up Secure Mode to keep your contacts
private"* motivates the setup without mentioning coercion. Never "one of your contacts may be
coerced."

**4. Custody and recovery traffic exempt from enforcement.** Shard operations do not travel on a
separate channel — they ride inside group bundles alongside messages, and a shard-only bundle signals
"no basket" with an empty message field (`OccultaApp.swift`, the `recipShardOps` / `recipManifest` /
`recipExpected` path). A naive "refuse to encrypt to this contact" catches custody traffic in the same
net, so trustees cannot send shards while the ban is up — closing the vault recovery path during
exactly the window that motivated the ban. **Enforcement must be at message-content level, not bundle
level.**

**5. The recipient's classification pinned to depth 0, not `currentDepth`.** Inbound processing is
depth-independent by design, but `saveClassification` writes `visibleThroughDepth` relative to
`currentDepth`. A ban processed while the recipient sits at duress depth N stamps the issuer with
ceiling N — visible at depths 0…N, the opposite of hidden. The ban silently does nothing, and only
for the users who most needed it. The setup *prompt* is safe from this (a recipient with no Secure
Mode cannot be at a duress depth); the classification write is not.

**6. Keyed to the contact identifier; lifts verified against the contact's current unexpired key.**
`reset(identity:)` (`Contact+Manager.swift`) expires a key while keeping the same `Contact.Profile`
and identifier — keys are a to-many relationship on the profile. So identity survives rotation, and
keying the ban to the identifier makes it survive too. Verifying a lift against the *issuing* key
instead would strand every ban the moment a key rotates.

**7. Mandatory expiry.** No unbounded bans. See below.

**8. The setup offer must not be modal on message open.** Offer it; let it wait. See "Accepted
limitations".

## Lifting

An explicit lift bundle as the only mechanism creates a permanent-DoS class — lose the phone, rotate
into a stranded state, or be detained past the point of caring, and the recipient can never message
the issuer again. It also makes a second broadcast unconditional. Four mechanisms, the bundle demoted
to the exception:

**1. Expiry — mandatory, and the default.** The ban carries a duration chosen at issuance and lapses
silently. No message, no artifact, no second broadcast. Resolves every loss case on its own, and
self-heals the backup-restore case where restoring a recipient's device from a snapshot taken during
the ban would otherwise resurrect a lifted one.

> **Do not apply SEC-1's lesson here.** The codebase's PIN lockout deliberately uses
> `ProcessInfo.systemUptime` rather than wall-clock, because a stored `Date` compared against
> `Date.now` is bypassable by changing the device clock. That reasoning does not transfer. It holds
> when the device holder is the adversary escaping a restriction; a ban's holder is a cooperating
> contact who, if they want to message early, can simply clear it locally (mechanism 3). Uptime would
> also break the feature outright, since it resets on reboot and a multi-week ban would not survive.
> **Wall-clock is correct here**, and someone will "fix" it by pattern-matching on SEC-1 unless this
> is written down.

**2. Implicit lift on re-pairing.** A fresh UWB exchange with that contact clears the ban. Physical
presence is the strongest available evidence that the ban should end, it is already this app's root
of trust, and it produces no artifact beyond an exchange that was happening anyway. Falls out of
requirement 6 for free: the new key becomes the contact's current key, so it can authorise the lift.

**3. Local clear by the recipient.** The holder can clear it on their own device. Costs nothing in
security — enforcement already runs on their device, under their control, and an old or modified build
ignores the ban entirely — and it removes the permanent-DoS class outright.

**4. Explicit lift bundle — early lift only.** When the issuer wants to end a ban before expiry and
cannot meet in person. The only mechanism that creates an artifact, and it is as innocuous as the ban
itself.

### Loss and rotation

| Scenario | Outcome |
|---|---|
| Issuer rotates key, same device | Identifier persists, ban persists, lift verifies against the new key |
| Issuer loses phone, re-pairs with recipient | Re-pair clears the ban (mechanism 2) |
| Issuer loses phone, never re-pairs | Attached to a dead key nobody can message anyway — inert, and expires |
| Issuer detained indefinitely | Expiry |
| Recipient loses phone | Ban gone with the device; the issuer's model was never verified anyway |
| Recipient restores a backup from during the ban | Ban returns, then expires |

## Accepted limitations

**It is a mitigation, not a control, and must be documented as one.**

- **Compliance is unverifiable.** No acknowledgement channel exists, and adding one would be another
  artifact and another broadcast. The issuer must still plan as though the ban failed.
- **Coverage is incomplete.** Contacts paired after issuance are not covered, non-Occulta contacts
  cannot be, and anyone who ignores it still sends. [Do Not Disturb](../Do%20Not%20Disturb/FINDINGS.md)
  covers this gap.
- **The recipient makes an irreversible choice reactively.** Activation rotates their DB key and
  deletes the old one, and requires a duress PIN they must remember — prompted by someone else's
  message. Hence requirement 8.
- **A coercer holding the unlocked device can issue bans.** `coercerBaseDepth`'s doctrine requires a
  depth-0 feature to exist at the coercer's home depth, or its absence is the tell. Harm is low once
  the message is innocuous, but it is a way to push setup prompts onto visible contacts.

## Open question

**Does an outbound bundle pad its recipient section to a constant count?** The on-device `Group` model
pads membership to 32 byte-identical filler slots specifically so counts cannot be read
(`Group+Model.swift`); no equivalent was found for an outbound bundle, and
`Crypto+Manager+GroupDecrypt.swift:99` only bounds `recipients.count <= Group.slotCount`. Unverified —
it rests on a negative grep. It only bites if requirement 1 is ever violated and the ban is addressed
selectively, but it should be settled before implementation.

## Objections raised and withdrawn

Four arguments against this feature were made at length on 2026-08-28 and do not survive: that the
recipient set is either the secret or the cover; that it manufactures a synchronised cross-device
trace; that concealment on the recipient is defeated by the transport; and that the disclosure moves
from artifacts to people. Each is recorded with its refutation in the oracle document, because each
sounded right and the same reasoning will be attempted again. Read them there before re-raising any
of them.

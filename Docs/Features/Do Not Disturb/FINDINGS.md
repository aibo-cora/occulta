# Do Not Disturb — Design Findings

**Status:** Proposed 2026-08-28. Not implemented, not scoped for a release. The smaller of the two
items and independently shippable — no protocol, no second party, no bundle format to settle.
**Context:** Design discussion, 2026-08-28. Extracted from
`Docs/Bugs/v1.10.0/Non-Safe-Sender-Rejection-Is-A-Duress-Detection-Oracle.md`.
**Companion:** [Message Ban](../Message%20Ban/FINDINGS.md). The two are complements, not
alternatives — they fail in opposite directions.

---

## Read this first

The leak this mitigates is **an accepted, documented limitation, not an open bug** — see the Message
Ban findings' equivalent note, and the 2026-08-13 decision in the oracle document. It has been
re-filed as a bug twice (Bugs 103 and 104) and closed both times. Do not gate the render, and do not
reject inbound bundles.

## What it is

A user-set quiet mode that silently queues **all** inbound and renders nothing, applied identically at
every depth.

## Why it is not the "silent queueing" already rejected

The 2026-08-13 table rejected a row called *"silently queue until depth 0"*, and the difference
between that and this is the entire point.

That option queued **selectively** — only messages from contacts hidden at the current depth — which
is why "nothing happens on tap" became an outcome reachable only under duress, and why it was rejected
as trading a strong signal for a weaker one rather than removing one.

DND queues **unconditionally**: every sender, every depth, on a switch the user set themselves.
Nothing about it varies with depth, so there is no signal to weaken. It is a different mechanism that
happens to share an implementation surface, and conflating the two will get it rejected for a reason
that does not apply.

## Why it is worth building

It is the only option raised against this residual that **adds no new observable anywhere**:

- no depth-conditional difference — nothing for a coercer to distinguish, so not an oracle;
- "Do Not Disturb" is an ordinary feature, so its presence is cover rather than signal, unlike
  `"Anonymous"` or a rejection error;
- no bundle, no recipient set, no remote party, no cross-device correlation;
- unilateral — needs nobody else to cooperate, and works immediately on a new device.

## The requirement that actually needs designing

**The switch is benign; the queue is not free.**

An earlier draft claimed DND needs no new stored state and therefore none of the `AppLayerConfig`
discipline. That holds for the *toggle*, which conceals nothing and can sit in the clear. It does not
hold for the *queue*.

Inbound messages today render transiently and are **never written as `Contact.Message`** — the oracle
document's own inbound-path trace establishes this, and that transience is why the inbound path
currently leaves so little behind. A quiet period converts it into deliberate persistence: inbound
files held on disk for as long as the user leaves DND on, which may be weeks. That lands directly next
to Bug 101, which found opened files sitting unsealed in `Documents/Inbox`.

So: **the queue must be sealed at rest, must not accumulate plaintext, and must have a defined bound
and eviction rule.** An unbounded plaintext spool of everything received during a coercion-adjacent
period is a worse artifact than the leak DND was meant to reduce. This is the part that needs
designing; the toggle is trivial.

## Limits

A coercer holding the phone can switch it off, after which the queue drains and renders. So DND does
not close the residual — it converts an automatic leak into one requiring a deliberate act by someone
who does not know there is anything to look for.

## Relationship to the Message Ban

| | Ban | DND |
|---|---|---|
| Enforced on | sender's device | your device |
| Needs others to cooperate | yes | no |
| Contacts paired after issuance | not covered | covered |
| Non-compliant or old builds | not covered | covered |
| Between ban expiry and renewal | not covered | covered |
| Available immediately after losing your phone | no — requires re-pairing everyone | yes |
| Stops the message existing | yes | no, queues it |
| Defeatable by the coercer holding your phone | no | yes, by toggling it off |

The ban prevents traffic at the source but depends on other people and leaves coverage gaps; DND is
unilateral and complete but only defers, and only until someone thinks to turn it off. Neither closes
the residual alone, and neither creates a new observable. That is the argument for both.

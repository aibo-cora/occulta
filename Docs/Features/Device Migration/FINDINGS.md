# Device Migration — Design Findings

**Status:** Exploratory design, 2026-10-02. No code yet; not scoped for a release. D-01 to D-05
decided; Q-03, Q-05 and Q-07 open.
**Context:** Design discussion, 2026-10-02. Proposal: a phone-to-phone sync that moves contacts and
the vault from an old phone to a new one, carrying only what is visible at the depth the old phone
is unlocked at.

**Problem statement.** Replacing a phone today loses everything local. The vault comes back only
through a `.occbak` restore plus a quorum of trustees ([`VAULT_BACKUP_GUIDE.md`](../../../Occulta/Features/Vault/VAULT_BACKUP_GUIDE.md),
*Import flow*), which is heavy for a routine upgrade. Contacts are rebuilt by hand. Bug 82
(`Docs/Features/Secure Mode/bugs.md`) puts this event at once every two to three years per
relationship, per side. It is certain, not rare.

**What this feature is not.** It does not move relationships. Identity is the Secure Enclave key,
which is non-exportable ([`contact-backup-analysis.md`](../../../Occulta/Features/contact-backup-analysis.md)),
so the new phone has a new identity whatever we do. Every contact still needs one physical
re-pairing with the new phone. The sync makes that re-pairing restore an existing record instead of
creating one from scratch, and it moves the vault without a trustee round.

---

## Decisions

### D-01 · No Secure Mode gate

**Decided 2026-10-02.** The original proposal allowed the sync only with Secure Mode active. Dropped.

**Why:** the gate adds no protection. Without Secure Mode there is only depth 0, so "the data
visible at the unlocked depth" is already "what the owner sees". The protection comes entirely from
D-02. All the gate would do is force people to set up duress PINs they don't want just to change
phones.

### D-02 · The sync carries only what is visible at the unlocked depth

**Decided 2026-10-02 (the original proposal's core constraint).** A coercer who drives the sync
from a duress depth gets a copy of what is already on their screen, and nothing else.

This is consistent with existing behaviour: `exportBackup(currentDepth:)` is already depth-scoped
([`Vault+Manager+Backup.swift:143`](../../../Occulta/Features/Vault/Vault+Manager+Backup.swift)), Bug 88 and Bug 114.
Vault entries match their depth exactly. Contacts are visible at every depth up to their limit, with
`originDepth` confining contacts created at a duress depth to that depth.

### D-03 · The new phone starts a fresh backup key

**Decided 2026-10-02.** The `BackupEncryptionKey` never leaves the old phone. The new phone has no
backup key until the owner sets one up and distributes pieces to trustees, as after a restore
(`VAULT_BACKUP_GUIDE.md`, *SSS redistribution and contact re-establishment after import*).

**Why:** carrying it buys nothing. The key is stored per depth since 2026-09-11, so sending the
current depth's key would behave the same at every depth and is not an oracle. But once trustees
re-pair with the new phone they see the owner fingerprint changed, and `mismatchHandbackOps` hands
their pieces back, so the old coverage is gone either way. A fresh key also keeps the backup key
from ever leaving a device. *Consequence:* no backup coverage on the new phone until the owner sets
it up. The post-import guidance says so.

### D-04 · The duress setup does not carry over

**Decided 2026-10-02.** Accepted for v1. Because of R-1, a real owner migrating from depth 0
arrives with no PINs and no layers, and must reclassify contacts and recreate decoys on the new
phone.

**Why:** carrying layer structure safely would need a duress-depth sync to produce something with
the same structure, so that the coercer's receiving phone can't tell the two apart. That is a
separate design and is not part of v1.

### D-05 · Custody shards held for others stay behind

**Decided 2026-10-02.** `CustodyShard` rows are not carried.

**Why:** the existing machinery already heals a trustee's phone change. When the owner re-pairs
with the trustee's new phone, our key change makes the owner's phone re-send the same backup key
(`reconcileBackupPieces`, `ShardCustody+Manager.swift:516`). Carrying shards would only have covered
one gap: the owner losing their own phone after we migrated but before the two of us re-paired. That
gap doesn't justify a depth filter over custody rows, the legacy rows that can't be attributed to an
owner (`ownerContactIdentifier == nil`), and a re-seal path. *Consequence:* until the owner re-pairs
with our new phone, their coverage is one piece short. The rows stay on the old phone until it is
erased (R-2).

---

## What moves and what doesn't

| Data | Moves? | Notes |
|---|---|---|
| Contact fields (names, phones, notes, photos…) | Yes, if visible at the current depth | Inserted as new keyless contacts (see below) |
| `Contact.Profile.Key` records (contact public keys, including ML-KEM material) | **No** | R-4 |
| Forward-secrecy state, prekeys (own and contacts') | **No** | Our prekey private halves are Enclave-bound per contact (`Prekey.swift`); a contact's one-time prekeys used from two phones would be reused |
| `signedAttributes` | **No** | Owner-side trustee state tied to the old identity; rebuilt when the owner sets up the fresh backup key (D-03) |
| Vault entries | Yes, if visible at the current depth | Re-sealed on arrival under the new phone's vault key, through the existing import path |
| `BackupEncryptionKey` | **No** | D-03 |
| `CustodyShard` rows (shards held *for* others) | **No** | D-05 |
| PINs, Secure Mode configuration, depth stamps | **No** | R-1, D-04 |
| Messages, drafts, groups | No | Out of scope; undecryptable on the new identity anyway (Bug 82) |

**Contacts arrive keyless.** That is an existing, ordinary state: contacts imported from the system
address book (`createContacts(from:)`, `Contact+Manager.swift:83`) have no key until an exchange. So
the new phone never shows a contact as reachable when it isn't, and no new "awaiting re-pair" state
is needed. Re-pairing is the existing flow: open the contact, run the exchange, and
`update(key:for:)` attaches the key ([`KeyExchange.swift:288`](../../../Occulta/UI/Tabs/Contacts/Key+Exchange/KeyExchange.swift)).

---

## Design rules

Each rule names the duress-depth observable or coercer action it prevents. The test for every one:
*does the change create an observable that can only occur at a duress depth, or let a coercer
trigger something they couldn't before?*

**R-1 · The receiving phone gets everything flat.** No PINs, no Secure Mode configuration, no
`visibleThroughDepth`, no `originDepth`, no vault-entry depth stamps. Everything is inserted through
the ordinary depth-0 paths on the new phone (contacts stamped `Int.max`, vault entries stamped 0).
*Blocks:* a structural difference in what lands on the receiving phone. If a depth-0 sync carried
layer structure and a duress-depth sync didn't, the coercer would learn from their own phone that
the source was at a duress depth. Copying the stamps would also leak depth numbering. *Cost:* D-04.

**R-2 · The source never deletes anything as part of a sync.** No "move", no "wipe after transfer".
The old phone keeps working until the owner retires it through the existing Erase All Data path.
*Blocks:* a coercer at a duress depth using sync-then-wipe to destroy the hidden data. Wiping only
from depth 0 would be a depth-dependent behaviour they could test for. Related:
`Docs/Bugs/v1.10.0/Erase-All-Data-Reachable-By-Coercer-With-Zero-Confirmation.md`.

**R-3 · The sync is offered at every depth with identical UI and flow.** *Blocks:* its absence, or
any difference in how it looks, giving the depth away. Payload size and duration scale with the
visible data, which the coercer can already see on screen, so they are not an oracle. The source
does the same work as `exportBackup(currentDepth:)`: it decrypts every entry's depth stamp to filter.
That is the export's existing timing profile, not a new one.

**R-4 · No key material leaves the old phone.** No identity material (impossible anyway), no
prekeys, no ML-KEM shared secrets, no contact key records, no backup key (D-03), no custody shards
(D-05). *Why:* all of it is bound to the old identity or superseded on the new phone, and some of it
(one-time prekeys) becomes dangerous if two phones use it. Dropping contact key records is also what
makes contacts arrive keyless (see above).

**R-5 · Withdrawn 2026-10-02.** Covered how custody shards would be filtered by depth. No longer
needed, because custody shards don't move (D-05). The number is kept so that references to R-6
through R-8 stay stable.

**R-6 · Nobody is contacted.** The sync sends nothing to any contact: no "I moved", no key-update
notice, no signed rotation. *Why:* letting a contact accept the new key on the old key's signature
is the self-vouching pattern already rejected twice (`Docs/Features/Multi-Device Contacts/FINDINGS.md`,
Design Sessions 3 and 4). Under coercion it would push an attacker's phone to the whole contact
graph in one event. Every contact re-pairs physically with the new phone.

**R-7 · The channel is the owner's own two phones in a physical ceremony.** The same proximity and
Diceware word confirmation as a contact exchange (`Exchange+Manager.swift`), with the payload
sealed under a one-time session key from ephemeral key agreement (P-256, plus ML-KEM-768 behind
`#available(iOS 26, *)` as in `PostQuantumProvider`). Neither phone's identity key is involved and nothing
is trusted beyond this one transfer. The old phone requires vault unlock (biometric) before it
sends vault content, exactly as export does today.

**R-8 · No migration record on either phone.** No "migrated on" flag, no log, no per-depth export
metadata update on the source. A residual remains: every record on the new phone shares one creation
window. That shows a migration happened, but the same is true at every depth and after any restore,
so it reveals nothing about depth.

---

## Flow

1. **Old phone**, unlocked at depth *d*: Settings → *Move to a new iPhone*. Requires vault unlock.
2. **New phone**, fresh install: *Move from my old iPhone*.
3. Proximity session, Diceware words confirmed on both screens (R-7).
4. Old phone gathers contacts visible at *d* (fields only) and vault entries visible at *d*
   (decrypted, as export does). It seals them under the session key and sends them.
5. New phone inserts contacts through the ordinary depth-0 path and vault entries through the
   existing import path (fresh per-entry keys under its own vault key, depth 0), then zeroes the
   session key.
6. New phone shows post-import guidance: re-pair with each contact, set up a backup key and trustees
   (D-03), and set up Secure Mode if wanted (D-04).
7. Old phone: unchanged (R-2).

---

## Threat analysis

| Who | What they get | Assessment |
|---|---|---|
| Coercer, old phone at duress depth *d* | A copy of depth *d*'s data on their phone | Intended. Equals what is on screen (D-02); structure gives nothing away (R-1); can't destroy anything (R-2) |
| Coercer with the compelled real PIN (depth 0) | Everything visible to the owner, in bulk | **Residual, proposed for acceptance (Q-03).** Already readable on screen; the sync only makes it faster |
| Thief with a locked old phone | Nothing | The sync needs an unlocked app and vault unlock |
| Malicious receiving app | Whatever the source sends | The same as the row above, since the source decides what to send |
| Eavesdropper during the transfer | Nothing | One-time session key, proximity plus confirmed words (R-7) |
| Forensic examination of either phone afterwards | That a migration occurred, on the new phone only (R-8) | Not depth-dependent |
| Contacts | Nothing until they re-pair | R-6 |

**Marginal change vs today (Q-03).** Today the vault only leaves the phone as a `.occbak` that needs
*k* trustees to open. With this feature, it can leave in a form a second device can read straight
away, gated only by the old phone's own unlock and vault biometric. Inside the threat model that is
not new *access*: whoever passes those gates can already read every entry on screen. But it removes
the trustee quorum as a barrier between the phone and a readable copy elsewhere. That is a real
change to state, and it needs explicit acceptance.

---

## Checked against prior decisions

- **No self-vouching** (`Multi-Device Contacts/FINDINGS.md` Design Sessions 3–4, `ROADMAP.md` R1):
  respected by R-6. ⚠️ `Docs/Features/Feature Evolution & Trajectory.md` item 2 ("Contact Migration
  Protocol"), where the old key signs the new one, contradicts that later decision and is
  **not** what this design does. That entry has not been edited here.
- **Depth-scoped export** (Bugs 88, 114): reused, not reimplemented.
- **Restore completion and backup-key layering** (Bugs 99 and 102, `VAULT_BACKUP_GUIDE.md`
  *What is not layered today*): the sync runs no restore and carries no backup key (D-03), so it
  opens neither hole.
- **Shard custody** (`Docs/Bugs/v1.10.0/Shard-Custody-Not-Cleaned-Up-On-Contact-Deletion.md`,
  `decisions.md` shard-visibility entries): not touched, since custody shards stay behind (D-05).
- **Non-safe-sender oracle** (`Docs/Bugs/v1.10.0/Non-Safe-Sender-Rejection-Is-A-Duress-Detection-Oracle.md`):
  not touched, since the sync carries no inbound messages.
- **Erase All Data** (`Docs/Bugs/v1.10.0/Erase-All-Data-Reachable-By-Coercer-With-Zero-Confirmation.md`):
  R-2 adds no new destructive path.

---

## Open questions

**Q-01 · Backup key on the new phone.** Resolved 2026-10-02 → D-03.

**Q-02 · Losing the duress setup.** Resolved 2026-10-02 → D-04.

**Q-03 · Accept the depth-0 bulk residual?** See *Marginal change vs today*.

**Q-04 · Legacy custody shards with `ownerContactIdentifier == nil`.** Moot since D-05.

**Q-05 · Transfer size.** Vault entries plus contact photos may exceed what one MultipeerConnectivity
message comfortably carries. Chunking must not change the observable shape across depths beyond
total size (R-3). Check against `Docs/Features/Bundle/Streaming Large Attachments — Problem Statement.md`.

**Q-06 · Carry custody shards at all?** Resolved 2026-10-02 → D-05.

**Q-07 · Old backup pieces handed back to the new phone.** Split out of Q-01. After D-03, trustees
re-pairing with the new phone hand back their pieces of the *old* backup key, and these are absorbed
into the restore buffer even though there is nothing to restore. This is existing behaviour for any
owner key change, not new here. It still needs confirming that it's harmless, including that a
banked old key can't complete a restore of an old `.occbak` at a depth it shouldn't
(`decisions.md`, *Filter restore shards by trustee visibility at completion*).

---

## Testing plan

Each decision and rule gets a test before it counts as done:

- **D-02:** a fixture with contacts and vault entries spread across depths 0, 1 and 2. A sync at
  each depth carries exactly the set `visibleContactIdentifiers(atDepth:)` and
  `entriesVisible(atDepth:)` select. Nothing more, nothing less.
- **R-1:** the payload *schema* is identical for syncs from depth 0 and from depth 2 (same keys,
  same types, no depth fields). Received rows carry the depth-0 stamps.
- **R-2:** row counts on the source are unchanged after a sync at every depth.
- **R-4 / D-03 / D-05:** the payload contains no `contactPublicKeys`, prekeys, FS state,
  `signedAttributes`, backup key, or custody shards. After the sync the new phone has no
  `BackupEncryptionKey` and no `CustodyShard` rows.
- **R-6:** no outbound bundle or shard operation is queued during or after a sync.
- **Keyless contacts:** a migrated contact accepts a key through `update(key:for:)` and becomes
  reachable, exactly as a contact imported from the address book does.
- Key-material tests inject `TestKeyManager`; where no seam exists, gate with
  `.enabled(if: secureEnclaveAvailable())`, never with the legacy print-and-return skip.

## Data migration

No schema change on either phone. The source only reads, and the receiver inserts through existing
paths. No SwiftData migration is needed, and nothing on the old phone is at risk (R-2).

---

## Related documents

- [`VAULT_BACKUP_GUIDE.md`](../../../Occulta/Features/Vault/VAULT_BACKUP_GUIDE.md): the export/import
  spec whose import and post-import paths this reuses
- [`contact-backup-analysis.md`](../../../Occulta/Features/contact-backup-analysis.md): why
  relationships can't be restored
- [`Multi-Device Contacts/FINDINGS.md`](../Multi-Device%20Contacts/FINDINGS.md): the no-self-vouching
  decision

## Known Bugs

| # | Summary | Status |
|---|---|---|
| — | None yet | — |

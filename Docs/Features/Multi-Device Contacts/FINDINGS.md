# Multi-Device Contacts — Design Findings

**Status:** Exploratory — no SPEC.md yet, not scoped for a release
**Context:** Design discussion, 2026-07-02. Captures conclusions reached before any implementation, so the reasoning isn't lost before this gets formally scoped.

**Problem statement:** A contact who owns more than one paired device (phone + backup phone, personal + work) should be reachable by a single send, openable on any of their devices that completed key exchange. Today `Contact.Profile` models exactly one active key at a time — a second device pairing would rotate/overwrite the first device's key rather than adding to it.

---

## Confirmed / Verified

### D-01 · The group-messaging envelope already fits this with no wire-format change

`OccultaBundle.GroupEnvelope` / `Recipient` / `RecipientPayload` (`OccultaBundle.swift:465–505`) wraps a random session key separately per recipient *key*, with trial-decryption slot-finding and no cleartext hint of which slot belongs to whom (`Crypto+Manager+GroupDecrypt.swift`). The abstraction was already "one slot per key to wrap for," never "one slot per contact" — confirmed by `GroupRecipient` (`Crypto+Manager+GroupEncrypt.swift:15–25`) taking `publicKey` / `quantumMaterial` / `contactPrekey` directly, with no contact identifier threaded through the crypto layer at all.

**Conclusion:** feeding one `GroupRecipient` per device-key belonging to the same contact works today, unchanged, at the bundle format level. All required changes are upstream of the crypto layer.

---

### D-02 · Per-device prekey pools are a hard requirement, not an inefficiency

Prekey private halves are Secure Enclave-bound (`Prekey.swift:24–31`, tag `"prekey.<contactID>.<id>"`) — non-exportable, non-syncable across devices by construction. There is no cryptographic way for one device to generate a prekey whose private half also exists on a second device. This mirrors Signal's resolution to the identical problem: multi-device isn't one identity with a shared pool, it's N independent per-device sessions fanned out at send time. Nothing to optimize away here — the "efficiency" work is in transport/administration, not the crypto:

- SE tag extends to `"prekey.<contactID>.<deviceID>.<id>"`. Verified this stays compatible with the existing contact-wide cleanup `seTagPrefix(contactID:)` (`Prekey.swift:67–69`), which prefix-matches and doesn't care what follows `contactID.`. A new `seTagPrefix(contactID:deviceID:)` becomes possible for revoking a single device's pool without touching the others.
- Pool depletion accelerates with device count: a multi-device send consumes one prekey per device per message (same mechanics as a group send today), so replenishment thresholds need to be evaluated per device, not per contact.

---

### D-03 · `deviceID` can be made as immutable as `contactID`, if minted the same way

Verified `Contact.Profile.identifier` (`Contact+Model.swift:12`) is `UUID().uuidString`, assigned once at contact creation, and never reassigned anywhere in the codebase (grepped all `.identifier =` call sites — no mutation path exists). It is not derived from the system Contacts framework or any other value that could shift.

`deviceID` doesn't exist yet, so this is a design choice, not a discovered constraint: mint a random UUID once, at the moment a specific device's key is first exchanged, and store it as a field on the `Key` record (`Contact+Model.swift:246–281`) — never derive it from anything observable (device name, OS version, etc.). Done this way, it's exactly as stable as `contactID` and safe to use in an SE tag prefix.

**Edge case (not yet resolved):** if a contact's device is wiped/reinstalled, its SE identity key regenerates and re-pairing produces a new key with a new `deviceID` — the old slot's prekey pool becomes orphaned. This is the same shape of problem single-device key rotation already has, just now scoped per-device. Cleanup-on-expiry, not a tag-stability problem. Overlaps with the "Contact Migration Protocol" projected feature (`Feature Evolution & Trajectory.md`, item 2) — signed key rotation would let a legitimate re-pair carry continuity forward instead of silently orphaning the pool.

---

### D-04 · Per-recipient prekey replenishment already exists and needs no new mechanism

`RecipientPayload.prekeyBatch` (`OccultaBundle.swift:501–504`) already carries the sender's fresh prekeys for one specific recipient slot, explicitly documented as mirroring the single-recipient replenishment logic. `GroupRecipient.pendingBatch` (`Crypto+Manager+GroupEncrypt.swift:24`) is built by `ContactManager` per recipient and sealed into that recipient's own encrypted slot (`Crypto+Manager+GroupEncrypt.swift:153`).

**Conclusion:** for multi-device, `ContactManager` builds one `GroupRecipient` per (contact, device) pair instead of one per contact, each carrying that device's own `pendingBatch` computed against that device's own threshold. The batch travels inside that device's own encrypted slot — device A never sees device B's replenishment prekeys, which is a useful isolation property if one device is later compromised. No new struct, no new wire field. The only new code is upstream: `ContactManager` fanning out one recipient per device instead of one per contact.

---

## Open Questions (Unresolved)

### Q-01 · Revocation of a single device

`expiredOn` (`Contact+Model.swift:257`) is currently the only invalidation mechanism, and it's rotation semantics: one key expires, a new one becomes active. Multi-device needs "kill device B's key, leave device A's key active" — a concurrently-active-keys model, not a rotation model. Not designed yet.

### Q-02 · Pairing UX for "add another device to an existing contact"

Unclear whether re-running UWB pairing with someone who already has a `Contact.Profile` should be detected as "this is contact X, add a device" vs. treated as a brand new contact. No dedupe-by-identity flow exists today to hook into.

### Q-03 · Group cap interaction

The 32-member group cap (`b702ce4`) counts recipient slots. If each device of a multi-device contact consumes its own slot, a contact with 3 devices in a group send costs 3 of the 32 slots. Not yet decided whether that's acceptable or whether multi-device contacts should be capped separately.

---

## Prerequisite for implementation

`Contact.Profile`'s key model must move from "one active key, rotation history" to "several concurrently-active keys, one per device" before any of D-01–D-04 can be implemented. Q-01–Q-03 should be resolved (or explicitly deferred with a documented reason) before writing a SPEC.md.

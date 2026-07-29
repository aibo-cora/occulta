# Message Persistence — Design Findings

**Status:** Exploratory — no SPEC.md yet, not scoped for a release
**Context:** Design discussion, 2026-07-14. Originates from the friction report's Sweep 2 (`Friction/USER_ENGAGEMENT_FRICTION.md`, C3/H1/H2) — "one persisted store + one inbox UI + one notification hook" for drafts, message history, and inbound delivery. Captures the security investigation done before any schema or code is written, so the reasoning isn't lost before this gets formally scoped.

**Scope narrowed 2026-07-14.** Sent/received message-history persistence (C3, H2) is deferred, not decided against permanently — the findings and options below (D-01–D-12, Options B–H) remain the reference if that work resumes later. What's moving forward now is drafts only (H1 — composition state loss), which turned out to be a meaningfully smaller and simpler problem once separated from unbounded message history: see "Drafts — Resolved Design" below for the settled schema, key scheme, and purge behavior.

**Authoritative framework:** `Occulta/Features/SecureMode/forensic-trace-avoidance.md` already documents this exact class of problem in depth (blob forensics, SQLite forensics, keychain forensics, UI tells, content gating) for contacts and vault entries. Findings below are written against that doc's existing severity scale and measures (`C1`/`C2`/`S5`/`S7`/`S8`/`K1` etc., cited directly below) rather than reinventing the framework — message persistence should extend it, not sit beside it.

**Problem statement:** Nothing survives past the current view. Composing a message and navigating away loses it; receiving a message shows it once and discards it; nothing tells the user something arrived while the app was closed. Fixing this means persisting message content for the first time anywhere in the app — which raises a forensic question this doc exists to work through carefully before any schema is written: does persisting messages create a way to detect the existence of a contact someone has hidden?

---

## Persisting Messages

### D-01 · Draft/attachment loss is confirmed, and worse than the friction report described

`ComposeViewModel` (`Occulta/UI/Tabs/Contacts/V2/ComposeViewModel.swift:20-38`) holds `messages`/`draftText` as plain in-memory `@Observable` properties — no SwiftData backing. `Contact.DetailsV2` (`ContactDetailV2.swift:23,28`), `Contact.DetailsV3`, and `GroupDetailV3` (`GroupDetailV3.swift:26,30,114`) all create a fresh `ComposeViewModel` per view instance and call `.onDisappear { self.composeVM.cleanup() }`. `cleanup()` doesn't just let the draft go stale — it actively deletes every attachment file from disk. Leaving mid-composition (back button, backgrounding, a phone call) destroys unsent attachments immediately, not just failing to save them. Confirmed identical in both the V2 and V3 compose UIs.

### D-02 · Inbound delivery is fully ephemeral

`OwnedBasket` (`Occulta/Data Models/Transfers.swift:13-22`) is a plain `Codable` struct, held as `@State private var openedFileContents: OwnedBasket?` in `OccultaApp.swift:178`, shown once via `.sheet(item:)`, with attachment files deleted on dismiss. No message history exists anywhere — closing the sheet discards it permanently.

### D-03 · Notifications: zero usage, confirmed

`grep -rn "UNUserNotificationCenter\|UNNotificationRequest\|import UserNotifications"` across the whole target returns no matches.

### D-04 · A dormant persistence model already exists, but doesn't fit

`Contact.Message` (`Occulta/Data Models/Message.swift:11-35`) is a real `@Model` class, registered in the SwiftData schema (`OccultaApp.swift:42`), but never inserted or queried anywhere in the codebase — dead scaffolding from an earlier, abandoned attempt at this same feature. It's thin (`origin: String?`, `recipients: [Data]?`, `content: Data?`) and doesn't map to what the UI actually renders (`Occulta.File`/`Basket`). Worth extending rather than building a parallel model, but it needs real work, not just wiring up.

### D-05 · Two tiers of duress protection already coexist, and the simple contact toggle only gets the weaker one

Traced how "mark contact sensitive" (`ContactFormV2.swift`'s "Private contact" toggle) actually protects data, since any new persisted-message table needs to fit into whatever that mechanism already provides:

- **Tier 1 (weak).** `ContactManager.setVisibility(for:isSensitive:)` (`Occulta/Services/ContactManager+Classification.swift:73-85`) sets `contact.visibleThroughDepth = try JSONEncoder().encode(isSensitive ? depth : Int.max).encrypt()` — an AES-GCM-sealed `Int`, but decrypted and compared in plaintext (`value >= currentDepth`) at read time, under the same canonical key at every depth. `VaultEntry.visibleThroughDepth` (`Vault+Model.swift:189`) uses the identical pattern; `Manager.Security.isEntryVisible(_:)` (`Manager+Security.swift:1140-1146`) and the contact equivalent `isVisible(_:atDepth:)` (lines 1129-1135) both just decrypt-then-compare. Crucially: **the row never leaves the database.** `ContactsListV2.swift:23` fetches every contact — sensitive or not — via an unfiltered `@Query` (impossible to filter ciphertext at the SQL level) and hides them only via `.filter { security.isDisplayable($0) }` at `ContactsListV2.swift:34`. Anyone with the raw SQLite file has every row, always; protection is UI-only.
- ~~**Tier 2 (strong).** Full Secure Mode duress activation... physically *removes* sensitive contacts from the queryable store... At a shallow depth those bytes genuinely don't exist in the queryable database — structural absence, not a filter.~~ **Corrected — this was factually wrong, confirmed twice: once narrowly (the "Key" section's `fileEncryptionKey`/`fetchContact` claim, corrected in the Drafts section below), and now here at the source.** `activateSecureMode` never removes a sensitive contact's row. Every profile — safe or sensitive-at-this-layer — gets looped over and re-encrypted under the staged key (`Manager+Security.swift:475-478`), with the code's own comment stating it plainly: "Sensitive contacts remain in the DB (not hard-deleted)... Depth-based visibility... controls what appears in the UI — not the key" (`:469-472`). `hardDeleteContact(_:)` (`Contact+Manager.swift:477-480`) exists with a doc comment claiming "Only for use in Secure Mode activation" — but has exactly one occurrence in the entire codebase: its own definition. Zero call sites, anywhere. The `LayerStore` blob a sensitive contact also gets pushed into (`Manager+Security.swift:438-441`) is an *additional* restoration snapshot, consumed only during deactivation to reconstruct exact prior state (`ContactManager.restoreContact(_:using:stagedKey:aad:)`) — not a replacement for staying in the main store, and not a confidentiality mechanism. **There is no tier, at any point, that cryptographically isolates a contact's profile data from the canonical key.** Both "tiers" are UI-filter-only, identically — the only real difference between them is whether a restoration snapshot exists for deactivation, not whether the data is any more or less exposed while hidden.

**The per-contact "Private contact" toggle only gets Tier 1 — and, per the correction above, Tier 2 turns out to get the same cryptographic protection anyway, just with a restoration snapshot Tier 1 lacks.** Any forensic risk discussed below already exists for contacts themselves, before message persistence adds anything.

### D-06 · Corrected: `VaultEntry` has no contact linkage at all — the real retroactive-tagging gap is specific to messages

**Original version of this finding was wrong and is corrected here.** It claimed `VaultEntry`/`CustodyShard` rows fail to retroactively hide when a contact becomes sensitive. Re-checked: `VaultEntry` (`Vault+Model.swift:159-198`) has **no contact-identifier field at all** — it's a personal note/seed-phrase/key-token, not tied to any contact. There is no "contact went sensitive, did the vault entry retroactively hide" scenario, because that pairing doesn't exist in the schema.

What *does* reference a contact — `ShardRecord.contactIdentifier` — lives embedded inside `VaultEntry.shardDistributionEncrypted`, which is already an AES-GCM-sealed blob (`Vault+Model.swift:90-99`, "Serialised with JSONEncoder, then AES-GCM sealed with the vault key... Never persisted in clear"), not a queryable plaintext column. So the shard-distribution linkage is already protected by that field's own encryption, independent of anything `setVisibility` does.

**Confirmed separately:** `Manager+Security.swift`'s `activateSecureMode` (Step 8, per `forensic-trace-avoidance.md` §S7) already re-stamps **every** `VaultEntry.visibleThroughDepth` as hidden under the staged key during full Secure Mode activation, with an explicit fail-safe-to-hidden rule for nil/corrupt values ("an entry that is invisible in duress mode is a UX inconvenience; one that is visible is a security failure"). This is unrelated to any specific contact's sensitivity — it's a blanket pass over all vault entries at activation time.

**The real gap, restated correctly:** messages *do* have a genuine contact relationship (sender/recipient), unlike `VaultEntry`. `setVisibility` (`ContactManager+Classification.swift:73-85`) only touches the `Contact.Profile` row and `Group` rows via `cleanUpGroupDuressMembership` (lines 84, 114-123) — it has no path to a `Contact.Message` table. **If a contact is messaged normally and later marked sensitive, any already-persisted messages need their own retroactive depth-stamp, and nothing today would do that automatically** — this is a real gap, but it is new to the `Contact.Message` model being proposed, not an existing gap in `VaultEntry`/`CustodyShard` as originally claimed.

### D-07 · Corrected: linkage precedent is more guarded than first stated

**Original version understated this.** `CustodyShard` — the actual top-level `@Model` representing shards this device holds in custody for others (`CustodyShard+Model.swift:33-52`) — is documented as deliberately storing **no contact link at all**; identity lives only inside its own `encryptedPayload` (header comment, lines 7-15). The raw-identifier reference I originally cited (`ShardRecord.contactIdentifier`) is a different, embedded struct inside `VaultEntry`'s already-encrypted `shardDistributionEncrypted` blob (see D-06) — not a standalone queryable column. So the codebase's actual precedent, correctly read, leans *toward* guarded/no-plaintext-linkage, not toward "raw identifiers are the established convention." This strengthens the case in Q-01 below.

### D-08 · C2's unconditional duress-discard must be preserved exactly, not "improved" for plausibility

Traced `pendingFileData`'s handling in `OccultaApp.swift` directly: when the app is locked and a `.occ` file arrives, the raw encrypted bytes are queued with no processing (`:458`). `PINEntry(onAuthenticated:onDuress:)` (`:312-322`) wires `onDuress: { self.pendingFileData = nil; ... }` — an unconditional, sender-agnostic discard, confirmed to match `forensic-trace-avoidance.md` §C2 exactly ("Option B" — content never crosses the depth boundary because it's never decrypted until depth is confirmed normal). This is a deliberate design choice, not a gap: the team already chose maximum safety over plausibility (a duress session shows zero new messages arriving, even from ordinary non-sensitive contacts, rather than risk any differential handling by sender). **Message persistence must not touch this gate.** No `Contact.Message` row gets inserted for anything received while locked or under duress — insertion only ever happens from `processInboundFile`, which §C2 confirms only runs after normal-PIN unlock.

### D-09 · New-message depth-stamping at insert time is the natural implementation mistake

Distinct from D-06's retroactive gap: even with retroactive re-tagging solved, every *newly inserted* `Contact.Message` needs its `visibleThroughDepth`-equivalent field stamped from the sending/receiving contact's *current* sensitivity at insert time. The obvious first implementation — "just show messages normally" — defaults new rows to always-visible, which would make the very first message from an already-sensitive contact visible under duress regardless of how correctly everything else is built. `VaultEntry`'s own `addEntry` (`Vault+Manager.swift:213`) already stamps `visibleThroughDepth = encrypt(currentDepth)` at creation for this exact reason — message insertion needs the equivalent lookup-and-stamp step, keyed off the *contact's* sensitivity rather than the vault's own creation-time depth.

### D-10 · Message row count/timestamps risk the same tell §S8 already accepted for vault entries — and the same open question about protection tier

§S8 documents, as an explicitly accepted gap: `VaultEntry.id`/`createdAt` are plaintext columns, so a raw SQLite dump reveals vault entry count and creation times regardless of depth — accepted *specifically because* vault content requires a fresh biometric SE-key evaluation to open, so a duress examiner without forced Face ID sees "Vault Locked," no count leak. `Contact.Message` will have the identical row-count/timestamp exposure. Whether that's similarly acceptable depends entirely on **which SE-key tier protects message content** — the Vault's dedicated biometric-gated key (§S8's stronger tier) or the general canonical local-DB key used for ordinary contacts (§S5's weaker tier, derivable whenever the device is merely unlocked, no biometric prompt). This is a real, unresolved architecture decision (see Q-04) with a significant UX cost on the stronger side — Face ID per message versus weaker-tier protection for what may be the most sensitive content in the app.

### D-11 · Fixed-width encoding discipline (§K1) applies to any new field

§K1 documents Bug 51: encoding a gate-state flag as `Bool` leaked one byte of ciphertext-length difference versus `UInt8`, which doesn't. Any new depth/sensitivity field added to `Contact.Message` needs to inherit this same discipline — always-present (never nil, matching §S7/§K2's "always populated" rule), fixed-width encoding, constant ciphertext length regardless of value — rather than being designed fresh without this precedent.

### D-12 · Notification content gating is untouched ground, but the concept is already precedented

Confirmed zero `UserNotifications` usage anywhere in the target. But §C1 already names the exact race a real notification implementation would introduce: "a notification tap while in duress mode could surface a message from a sensitive contact before the depth gate could prevent it," mitigated today by suppressing the basket at set-time if the sender isn't safe. Local notifications, if added, need the same gate applied one step earlier — to notification *generation*, not just tap handling — following §K1's "opaque regardless of state" principle: notification content must not differ in a way that reveals whether the sender is sensitive (e.g. a generic "New message" for everyone, never a sender name, unless that sender's safety at the current depth has been confirmed).

---

## Linkage & Persistence: Options Considered

Six options were weighed for how a message relates to its contact, given D-08's constraint (never cross the depth boundary before normal unlock) and the forensic goal (don't let a hidden contact's existence be inferred from message data).

### Option B · Encrypted `contactID`, decrypt-all-then-filter, in-memory index built once per unlock

The design worked through in detail above (D-05–D-11). Tier 1: no queryable linkage at rest, protects against cold/offline forensic extraction, but doesn't close the live-duress case — the canonical key that decrypts the index is the same key derivable whenever the device is unlocked. Viable performance-wise *only* if the decrypt pass is a one-time per-unlock index build (mirroring `VaultManager.authContext`'s lifecycle — derived once, held in memory, wiped on `lock()`) with incremental updates for new messages, never a per-view or per-render rescan. A literal "decrypt everything, every time" implementation is not viable at power-user message volumes (estimated low seconds, serially, at ~100k messages).

### Option C · Deterministic pseudonymous tag for SQL narrowing — considered, rejected

A stable per-contact tag (e.g. an HMAC over contact key material) stored as a plaintext-but-non-identifying column would let SwiftData push a predicate instead of scanning everything. Rejected: a live examiner who already has key material for every *visible* contact can compute the same tags and identify which messages' tags don't match any visible contact — the identical tell as a raw identifier, just relabeled. Since Option B's in-memory index already solves the performance problem this was meant to solve, C buys nothing beyond B while offering a weaker guarantee.

### Option D · True structural separation (Tier 2 for messages) — the real fix, out of scope for this pass

Analogous to `activateSecureMode`'s `LayerStore` relocation for sensitive contacts: each contact's messages would live in a separate encrypted container, keyed by something only derivable if you already trust that specific contact, with no distinguishable row in the main store when hidden. This is the only option that closes the gap completely rather than raising the effort bar. It's also substantially bigger: `LayerStore`'s fixed-size-slot trick (§B3 — constant file size regardless of payload) works because it protects a *bounded* roster of sensitive contacts; messages are unbounded and continuously growing, so the same trick needs pagination/archival solved on top before it generalizes. Confirmed as its own initiative, matching Q-03 — not a Sweep 2 sub-task.

### Option E · Don't persist messages for sensitive contacts at all

If a contact is marked sensitive, their conversations stay exactly as ephemeral as they are today — no row inserted, nothing to find. Everyone else gets full persistence. Reuses existing shape: §C1 already suppresses a basket at set-time if the sender isn't safe; extending that same check to gate *persistence* during normal (non-duress) processing is a small extension, not new architecture. Fully closes D-10's row-count tell for exactly the contacts it matters for, since there's nothing to count. Honest residual: absence of messages is a *softer* signal than a correlatable orphaned row (it doesn't positively prove a hidden contact exists — plenty of ordinary contacts legitimately have little history), but it isn't literally zero information.

### Option F · Fold messages into the contact's own encrypted record, no separate table

If a message were just part of the already-hidden `Contact.Profile` payload, it would automatically inherit whatever protection that row already has — Tier 2 relocation moves it for free, and D-06's whole class of gap disappears by construction. Cost: AES-GCM seals a blob as a whole, not incrementally, so every new message means decrypt-entire-history, append, re-encrypt, rewrite the whole thing back — unboundedly more expensive as a conversation grows, which is the wrong shape for the workload that actually dominates (sending/receiving happens far more often than opening an old thread cold). Only attractive if per-contact message volume is expected to stay small.

### Option H · Accept the linkage tell, invest in content strength instead

Explicitly accept the row-existence/count tell (matching §S5 and §S8's already-accepted precedent for contacts and vault entries) and put the security budget into Q-04 instead — require the Vault's biometric-gated key tier for message *content*, so a live examiner who fully correlates "contact X has messages" still can't read them without forcing Face ID specifically. A deliberate prioritization (protect content over metadata), not a technical scheme — the same trade-off the codebase already made once (§S8: "the current gap exposes only metadata... without biometric coercion").

---

## Design Decisions

**Drafts will be self-encrypted, not stored plaintext or File-Protection-only.** Reuses the self key-agreement mechanism scoped for the Vault's encrypt-to-self feature (`privateKey.sharedSecretFromKeyAgreement(with: publicKey)`, deriving a stable symmetric key from one's own SE identity key) rather than introducing a plaintext exception or relying solely on iOS Data Protection. Keeps "plaintext never touches SwiftData" true without exception, matching `VaultManager`'s stated rule verbatim. Attachments stay encrypted on disk through drafting exactly the way they already are during active composition (`AttachmentManager.encrypt`/`streamingEncryptor`, per `ComposeViewModel.swift`) — no weaker-protection window while a draft sits unsent.

**Linkage/persistence: Option E + Option B, combined, not either alone.** Sensitive contacts get zero persistence (Option E) — no `Contact.Message` row is ever inserted for them, reusing §C1's existing suppress-at-set-time shape extended to the normal-unlock persistence path. Every other contact gets Option B's encrypted-`contactID` design with a once-per-unlock in-memory index (never a per-view decrypt-all). This closes the sharpest edge of the risk cheaply (Option E) where it matters most, without paying Option D's much larger structural cost for contacts where correlation isn't a meaningful concern in the first place (they aren't hidden). Option D remains the documented upgrade path if the threat model is ever elevated — deferred, not rejected, the same way Design B was already deferred for contacts themselves in §S5.

---

## Open Questions (Unresolved)

### Q-01 · RESOLVED — encrypted linkage for non-sensitive contacts; moot for sensitive ones

Settled by the Option E + B decision above. Non-sensitive contacts use encrypted `contactID` with a once-per-unlock in-memory index (Option B) — the guarded approach `CustodyShard`'s precedent actually supports (D-07's correction), not the raw identifier originally assumed. Sensitive contacts never get a `Contact.Message` row at all (Option E), so the linkage-field question doesn't apply to them — there's nothing to link.

### Q-02 · Retroactive re-tagging — narrowed, but one new sub-question opened by Option E

`setVisibility` still needs a new path for `Contact.Message`, but Option E changes what that path has to do: going forward, a contact marked sensitive gets zero new persisted messages, so there's nothing new to re-tag for them. The open question is what happens to messages that were **already persisted before the contact was marked sensitive** — do they get purged entirely (matching Option E's invariant that sensitive contacts have zero message history, full stop), or retroactively depth-tagged and left in place (weaker, but keeps history if the contact is later un-marked)? Purging is more consistent with Option E's own logic and simpler to reason about; retroactive tagging keeps more data but reopens exactly the kind of "existing row that should have been hidden" gap Option E was meant to avoid. Leaning toward purge-on-mark-sensitive, not yet decided.

### Q-03 · Tier 2 protection for messages is explicitly out of scope for this pass

Even with Q-02 solved and every `Contact.Message` row correctly Tier-1-tagged, rows still physically exist in the database regardless of depth — true structural hiding (Tier 2, `LayerStore`-style relocation) is a separate, larger security initiative that today only covers full Secure Mode contact activation. This should be named as a known, explicit residual limitation rather than silently left unaddressed or accidentally implied as solved by Sweep 2.

### Q-04 · What SE-key tier protects message content?

Raised by D-10. The Vault's dedicated biometric-gated SE key (fresh Face ID per access, strong protection, real UX cost) versus the general canonical local-DB key used for ordinary contacts (weaker — derivable whenever the device is merely unlocked, no biometric prompt, but no added friction). Message content is plausibly the most sensitive material in the app; using the weaker tier would make it the *least* protected sensitive content by that same logic. Not yet decided, and it determines whether D-10's row-count/timestamp exposure is an accepted trade-off (as §S8 already accepts for vault entries) or a problem that needs solving on its own terms.

---

## Prerequisite for implementation (message history — deferred)

Q-01 is resolved (Option E + B). Q-04 (SE-key tier) still needs an answer before the `Contact.Message` schema extension is written — it changes both the field shape and the UX. Q-02's purge-vs-retag sub-question should be settled before shipping, since it determines part of the `setVisibility` extension's behavior. Q-03 should be written down as a known limitation in whatever SPEC.md eventually follows this doc, not left implicit. D-08 (preserve §C2's unconditional duress-discard exactly) and D-09 (stamp new messages at insert time from current contact sensitivity) are not optional — either being missed breaks the existing security model rather than just leaving a gap in the new one. Option E's persistence gate (§C1-style suppression extended to normal-unlock processing) is now equally non-optional alongside them.

**This entire section is on hold per the 2026-07-14 scope narrowing above.** Nothing here blocks the drafts work below, which doesn't depend on `Contact.Message` at all.

---

## Drafts — Resolved Design

Scoped down from the full message-persistence problem: drafts don't accumulate the way sent/received message history would. At most one active draft per recipient at a time, replaced or cleared on send — bounded by contact count, not by message volume. That difference is what makes several of the hard problems above (Option B's performance concern, most of Q-01–Q-04) not apply here, or apply so cheaply they're not worth a separate mechanism.

### Model

Named `Message.Draft`, not `ContactDraft` — `Contact.Draft` already exists (`Contact+Draft.swift:14`) as an unrelated plain `Codable` staging struct for editing a contact's *profile* fields (name, phones, emails — what `ContactFormV2` binds to). No symbol collision either way, but confusingly close for anyone reading the code. `Contact` itself is a caseless namespacing enum (`enum Contact { }`, `Contact+Model.swift:7`); the new model gets its own parallel namespace instead of overloading `Contact`'s:

```swift
enum Message { }

extension Message {
    @Model
    final class Draft {
        var id: UUID = UUID()                  // row identity AND the folder name — opaque, no meaning outside this row
        var encryptedRecipientID: Data          // AES-GCM sealed contact/group identifier
        var encryptedContent: Data              // sealed Basket (text + attachments together) — see Content below
    }
}
```

No `visibleThroughDepth`-equivalent field, unlike `VaultEntry`/the deferred `Contact.Message` design — the sensitivity gate (below) runs *before* a row is ever inserted, so nothing sensitive-contact-shaped reaches the table in the first place. No plaintext timestamp either: draft count is small enough that decrypting all rows to sort/display costs nothing worth trading a metadata leak for.

`Draft`'s initializer requires `id` as an explicit parameter (`init(id:encryptedRecipientID:encryptedContent:)`), not a default-generated one. Both ciphertext fields are always sealed against a specific `id` via `Message.Draft.aad(id:field:)` before the row exists — the AAD has to be computed first, since it's the id that makes a fresh insert's AAD differ from what an update would reuse. A default-generated `id` decoupled from the one already baked into the ciphertext would produce a row that fails GCM authentication forever, with no separate "reassign it after construction" step to accidentally drop.

### Content: `Message.Draft.Payload` — a sealed `Basket`, plus the two things a `Basket` alone can't represent

A draft's committed content is bundled into the same `Basket` (`Occulta/Data Models/Transfers.swift:27-36`) already used for real sends — reusing the existing structure instead of inventing a separate draft format. `Basket`/`Occulta.File` alone turned out not to be quite enough, though — the compose UI has two things a `Basket` has no way to express, both of which matter for restoring a draft faithfully:

- **The current, not-yet-committed input field text**, separate from anything already "sent" into a `Basket`. Quick mode's whole composition lives here the entire time it's being typed, so this has to be persisted too, not just committed items.
- **Which compose UI (Quick vs Thread) the draft was composed in.** Thread mode's `ComposeViewModel.addText()` appends one `.text`-formatted `Occulta.File` to `messages` *per sent bubble* — a single draft's `messages` can hold several, interleaved with attachments, forming a whole conversation transcript, not just one string. An earlier version of this design tried to fold the current input text into the same `Basket.files` array as everything else and pick it back out by position (e.g. "the last `.text` entry is the input field") — that's exactly the kind of implicit convention this codebase has been burned by before, and it silently drops every thread text bubble except the very first, since the original code path only ever recognized one `.text` entry total. Restoring the wrong compose mode is a separate, compounding problem: reloading always defaulted to Quick mode, whose UI never displays `.text`-formatted entries in `messages` at all, so a restored thread's bubbles would still exist in memory but be invisible until the user hit Encrypt.

`Message.Draft.Payload` (`Occulta/Data Models/Message+Draft.swift`) is the small wrapper actually sealed into `encryptedContent`, resolving both explicitly instead of by inference:

```swift
struct Payload: Codable {
    var draftText:     String   // the input field, not yet committed
    var basket:        Basket   // committed items, in order — attachments and text bubbles alike
    var wasThreadMode: Bool     // which compose UI to restore
}
```

Attachments and already-committed text bubbles both live in `basket.files`, distinguished on load by `format`/`content` (an attachment has a reconstructed `url` and no `content`; a text bubble has `content` and no `url` — see "Attachment storage" below), not by position. Restoring `wasThreadMode` at load time turned out to have its own hazard — see "Restoring compose mode without re-triggering the wipe," below.

Full reuse of `ContactManager.encryptBundle(for:)` (`Contact+Manager.swift:938-1073`) was considered and rejected: it requires a real `Contact.Profile` — `fetchContact(by:)`, prekey pop/forward-secrecy state, version resolution — all genuinely contact-specific. Making "self" work through that path means inventing a synthetic self-contact, which is exactly the complexity already avoided once for the Vault feature (chose `VaultEntry.note` over a synthetic "You" contact). Not worth reopening for drafts.

What *is* reusable: the sealing primitive underneath is already generic. `Crypto+Manager+GroupEncrypt.swift:122-165` generates a random session key and does a plain `AES.GCM.seal(payloadData, using: sessionKey, ...)`, with recipient-specific ECDH key-wrapping happening as a separate step afterward — the seal itself doesn't know or care about contacts. The decrypt side already has the shortcut this needs: `open(_:using: SymmetricKey)` (`Crypto+Manager+ForwardSecrecy.swift:100`) takes a raw symmetric key directly, no contact lookup. The encrypt side has no counterpart yet — add a small `seal(sealedPayload:using: SymmetricKey)` mirroring it, calling the same already-generic internals. Small addition, not a restructuring.

### Key: the canonical local DB key for the row; the existing per-contact key for attachment files

The `Message.Draft` row itself (`encryptedRecipientID`, `encryptedContent`) is sealed under the canonical local DB key. Originally scoped as a two-layer scheme (a static self-key-agreement secret wrapping a separate, rotatable draft key) specifically so Secure Mode activation could destroy the wrapping key and crypto-erase every draft. Unnecessary: **the canonical local DB key already rotates on activation** — §S1 documents this as an existing, audited, Critical-severity mechanism ("the local DB key is `ECDH(ourSEKey_localDB, G)`... rotation... is the core reason the DB key rotates on activation," old key deleted after commit). Encrypting the row directly under this same canonical key gets the identical crypto-erasure guarantee for free, through a mechanism that's already built and already trusted, instead of a parallel one that needed auditing from scratch. It's also the more consistent choice given a decision already made below: drafts get Tier 1, not the Vault's biometric-gated tier — the canonical DB key *is* Tier 1, the same key already protecting `Contact.Profile.visibleThroughDepth` and everything else at that level.

**Attachment *files* stay under the existing per-contact key** (`ContactManager.fileEncryptionKey(for:)`) already protecting them during active composition — they are *not* re-sealed under the canonical key. This isn't the rejected two-layer scheme above (a *new*, purpose-built rotatable key wrapping something static) — it's simpler: reusing a key and a manager (`AttachmentManager`) that already exist and are already used for this exact content at every other stage of a message's life (composing, sending, displaying a sent thread). Re-sealing under the canonical key at save time was considered and rejected: it would cost a decrypt/re-encrypt round-trip per attachment, on top of the encrypt/decrypt `AttachmentManager` already does at send time, for no security benefit — see below for why.

Two things make the per-contact key safe here rather than a gap:

1. ~~`fileEncryptionKey(for:)` requires the contact's live `Contact.Profile` row... When a contact becomes sensitive-at-this-layer during Secure Mode activation, their profile is physically relocated out of the queryable store into the `LayerStore` blob (D-05's Tier 2). `fetchContact(by:)` then fails, and `fileEncryptionKey(for:)` throws — the per-contact key becomes undeirvable as a direct consequence of contact relocation.`~~ **Corrected — this was factually wrong, found while investigating the `isKnownContact` open item below.** `activateSecureMode` does not remove a sensitive contact from the main store at all: "Sensitive contacts remain in the DB (not hard-deleted)... Depth-based visibility (`visibleThroughDepth`) controls what appears in the UI — not the key" (`Manager+Security.swift:469-472`), and every profile — safe or sensitive — gets looped over and re-encrypted under the staged key (`:475-478`). `fetchContact(by:)` (`Contact+Manager.swift:400-404`) filters only on `identifier == identifier` — no depth check, no `deletionToken` check either. So `fileEncryptionKey(for:)` does *not* throw for a sensitive contact; it derives the same key it always would. The "blob" pushed to `LayerStore` (`LayerContact`) is a separate, additional restoration snapshot used by deactivation, not a removal of the row from the queryable store. Point 2 below was already carrying the real weight of this guarantee ("Point 1 above is real defense-in-depth, not the primary guarantee") — so nothing about attachments' actual safety changes, but there is one less real backstop than previously documented here: a sensitive contact's per-contact key stays fully derivable indefinitely, with no crypto-level fallback if a purge is ever missed.
2. **Explicit deletion, not key rotation, is the actual erasure mechanism** for attachment files, matching how they're already treated everywhere else in this codebase (`ComposeViewModel.cleanup()`/`clearAfterEncrypt()` delete files outright; nothing anywhere relies on rotating a key to make an attachment file unreadable). Point 1 above is real defense-in-depth, not the primary guarantee — the primary guarantee is that purging a draft (day-to-day sensitivity marking, or activation) deletes its attachment files, not just its database row. See "Attachment storage" and "Purge" below.

The row's own AAD is unaffected by any of this: `id + field`, the same construction as `VaultEntry.aad(for:)` minus its timestamp component. `Message.Draft` has no persisted creation date to bind one to, matching the no-plaintext-timestamp decision above. This still keeps `encryptedContent` bound to its own row even though the key is shared with the rest of the app's Tier-1 data.

### Attachment storage: separate files, referenced from the `Basket`, never inlined

**An earlier implementation of this design inlined every attachment's full plaintext into the sealed `Basket` on every save** — reading each file via `AttachmentManager`, JSON-encoding the raw bytes alongside the text, and sealing the whole thing as one `encryptedContent` blob. This was wrong in three compounding ways: a large attachment's *entire* plaintext got decrypted and re-sealed on every debounced save, not just when it actually changed; the resulting ciphertext (base64-JSON of raw bytes) could balloon `encryptedContent` to hundreds of megabytes for a single video, landing in a SQLite column and rewriting the WAL on every save; and a database or WAL file suddenly hundreds of megabytes larger than a normal contact/draft count would explain is itself a forensic signal, visible without decryption — a worse leak than anything §D-10 already accepted.

The fix: `Occulta.File` (`Transfers.swift:40-58`) already distinguishes `content: Data?` (inline plaintext bytes) from `url: URL?` (an on-disk reference) — exactly how attachments already work during active composition, before any draft-saving happens. Drafts preserve that shape instead of collapsing it. No separate manifest is needed — the `Basket` already is one; a `File` entry's existing `format` field (plus its own `id`) carries everything needed to find and describe an attachment, and the whole `Basket` is what gets sealed as `encryptedContent`:

- **Text** stays inlined via `content`, exactly as today — small, cheap to reseal on every save.
- **Attachments** are represented by an entry with no `content` and, deliberately, no stored `url` either — see "Getting it back on load" below for why.

**Where the referenced file lives:**

```
Application Support/Drafts/<draftID>/<file.id>[.<extension>]
```

One folder per draft, named by the row's own opaque `id` — never by the recipient's identifier, which would recreate the exact linkage tell this whole design avoids in the database, except worse: listing a directory requires no decryption at all. Each attachment inside it is named by its own `Occulta.File.id` — a stable UUID already assigned when the attachment was first added — with a real extension appended when one is known (`Message.Draft.attachmentFilename(for:)`), so AVFoundation's content-type detection for video playback (`AttachmentManager`'s `ResourceLoader`, which reads `URL.pathExtension`) still works after a reload. **Trade-off, not free:** a directory listing now reveals attachment *type* (`.mp4`, `.jpg`) via the filename, where the original design had none. Still never the original filename — that metadata stays inside the sealed `Basket`'s `format` field, never on disk in the clear — but this is a real, deliberate softening of the folder's opacity, not nothing. `.completeFileProtection` on every file, matching §S3. The folder never needs to know or expose which recipient it belongs to — that fact exists exactly once, encrypted, inside the `Message.Draft` row that stores the same `id`.

**Getting a file there:** on save, for each attachment, check whether `Drafts/<draftID>/<attachmentFilename>` already exists. If it does, do nothing — an attachment's bytes never change once added, so a prior save already has a durable copy and there's nothing to redo. If it doesn't, *copy* (not move, and not decrypt/re-encrypt) the file from its live compose-session temp-directory location into that path. Same key, same bytes, a plain `FileManager` copy — the only file-system work draft-saving does for an unmodified attachment set, and a one-time cost per attachment rather than a per-debounce one.

**Getting it back on load:** since the persisted file is already sealed under the exact key the compose UI's `AttachmentManager` already holds, `load()` doesn't need to decrypt-then-re-encrypt into a fresh temp copy. It also doesn't trust a `url` stored at save time — an earlier version of this design did, baking the full absolute path into the sealed `Basket`. That's fragile: Apple's own guidance is that a container path should always be re-resolved via API, not persisted and assumed stable, and a stale stored path would silently reproduce the exact class of attachment loss this whole feature exists to prevent. Instead, `load()` reconstructs the URL fresh every time from `Message.Draft.attachmentsFolder(for: row.id)` plus `Message.Draft.attachmentFilename(for: file)` — the same two pieces of information (`draftID`, `file.id`) both save and load always have on hand regardless of what the container path happens to be right now. Display, playback, and re-editing all work unmodified, since nothing about the file's protection or naming changes for the rest of the compose session. If the user removes that attachment mid-edit, the existing delete path (`FileManager.removeItem(at:)`) now deletes the persistent copy directly — correct, since removing an attachment from a draft should get rid of both the live and durable copies, not just one.

### Restoring compose mode without re-triggering the wipe

Each compose view has a pre-existing, pre-drafts behavior: switching `useThreadCompose` between Quick and Thread deliberately wipes the current composition (`ComposeViewModel.clearAfterEncrypt()`), since stale content from one mode isn't assumed safe to carry into the other. Restoring `wasThreadMode` at load time — a plain `self.useThreadCompose = loaded.wasThreadMode` assignment — runs straight into that: if the original binding for the toggle is `self.$useThreadCompose` and the wipe is wired to `.onChange(of: useThreadCompose)`, a *programmatic* restore assignment fires the exact same handler a *user* toggle does, wiping the `draftText`/`messages` the load just finished restoring, moments after restoring them. A guard flag to suppress the wipe during restore was considered and rejected: it can't be reliably reset. If the restored draft was already in Quick mode, assigning `useThreadCompose = false` is a no-op (same as the default) — `.onChange` never fires — so a flag meant to be cleared inside that handler never gets cleared, and silently suppresses the wipe on the *next real* user-initiated toggle too.

Resolved by moving the wipe out of `.onChange` entirely, into the toggle's own `Binding`'s setter, constructed by the parent view rather than passing `self.$useThreadCompose` directly:

```swift
ComposeStyleToggle(useThread: Binding(
    get: { self.useThreadCompose },
    set: { newValue in
        self.useThreadCompose = newValue
        self.composeVM.clearAfterEncrypt()
    }
))
```

This isn't managing the race, it removes it: the wipe now only ever runs when something calls through *this specific binding* — which only the toggle button's own tap does. A `.task`-time restore assignment (`self.useThreadCompose = loaded.wasThreadMode`) writes directly to the underlying `@State` property, never through the binding, so it can't trigger the wipe no matter what the before/after values are. No flag, no ambiguity between "is this a restore or a real toggle" — the two paths are structurally distinct, not inferred at runtime.

### Lifecycle: when a draft is actually written, read, and cleared

- **Persisted lazily**, not on every keystroke: at the same point `ComposeViewModel.cleanup()` currently fires (`.onDisappear`, backgrounding) — replacing "delete the attachment" with "run the sensitivity gate, then persist if not sensitive." Also flushed immediately on backgrounding (`scenePhase` leaving `.active`, wrapped in a `UIApplication.beginBackgroundTask` assertion) — `.onDisappear` alone only fires on navigation away, not when the app backgrounds while a compose screen stays on top.
- **Resumed on open**: when a compose view opens for a recipient, check for an existing `Message.Draft`, decrypt it, and load `draftText`, `messages`, and `useThreadCompose` back from the decoded `Payload` before the user starts typing.
- **Cleared on send, not on encrypt.** `ComposeViewModel.encrypt(for:...)` (`Contact+Manager.swift`-adjacent, `ComposeViewModel.swift`) is unchanged — it builds a *separate* `Basket`, sealed under the recipient's actual exchanged key via `contactManager.encryptBundle`, completely independent of how the draft itself was sealed. The `Message.Draft` row and folder are deleted at the same point `clearAfterEncrypt()` already fires today — from `ActivityView`'s completion handler, only `if completed` (the user actually sent, not just cancelled the share sheet). Cancelling the share sheet leaves the draft (and its persisted copy) intact for another attempt, exactly like today's in-memory-only behavior already does.

### Sensitivity gate (Option E, applied live, not stamped)

At save time (backgrounding, navigating away), check whether the recipient is *currently* sensitive. If yes, don't touch the table — today's ephemeral loss (D-01) continues unchanged for them. If no, upsert the row and folder. Because this check runs fresh on every save rather than storing a stamped value, there's no stale-flag problem the way messages would have had (D-09's concern doesn't apply here).

### Purge on `setVisibility(isSensitive: true)`

Find and delete that one recipient's `Message.Draft` row, and its entire `Drafts/<id>/` attachment folder if present — bounded, cheap, at most one row and one folder. The folder deletion is now the operative erasure step for any attachment content, per the per-contact-key reasoning above: nothing rotates that key at this point, so nothing else makes the file unreadable.

### Purge on Secure Mode activation — corrected: selective, not blanket

**An earlier version of this section said "delete every draft, blanket, no exceptions," and cited §S7 as the precedent. That citation was wrong, and the design was too destructive.** Re-checking the actual §S7 text: `VaultEntry` handling is a *preserve-and-rekey* pass, not a wipe — "Non-nil, readable — existing depth value re-encrypted under staged key **verbatim**." Non-sensitive vault entries survive activation intact; fail-safe-to-hidden is reserved for the ambiguous cases (nil or corrupt values) only. A blanket draft wipe would destroy every ordinary contact's draft for no reason, which isn't what the codebase's own pattern does elsewhere.

There's also a mechanical reason this needs to be an explicit, *selective* step rather than an afterthought for the row itself: since a draft row is sealed under the canonical DB key, and that key rotates at activation (§S1 — old key deleted, new key created), **every existing draft row becomes unreadable the instant activation runs unless something explicitly re-encrypts the ones that should survive.** Crypto-erasure for sensitive contacts' draft rows comes free from the key rotation; preservation for everyone else requires action, or it's lost too. Attachment *files* don't need this same treatment — per the per-contact-key reasoning above, a surviving contact's attachment files stay readable automatically (their key material survives alongside their re-encrypted profile), and a purged contact's attachment folder is deleted outright rather than needing any re-seal.

Sequenced right after (or alongside) contact classification — it needs to know which contacts are being moved into the sensitive/`LayerStore` set in *this* activation pass:

```
for each Message.Draft row:
    decrypt encryptedRecipientID (under the old canonical key)
    if undecryptable, or that recipient is being classified sensitive this activation:
        delete the row and its Drafts/<id>/ attachment folder
    else:
        decrypt encryptedContent under the old key
        re-seal encryptedRecipientID and encryptedContent under the new (staged) key
        update the row in place
        (attachment files: untouched — still valid under the surviving contact's
         still-derivable per-contact key, nothing to re-seal)
```

This gives two things at once: sensitive contacts' drafts (row and attachment folder) are actively deleted (explicit deletion as hygiene on top of the key-rotation crypto-erasure for the row, and as the *only* erasure mechanism for attachment files — not passive omission, since a future "re-encrypt everything" refactor pass could otherwise accidentally sweep a sensitive contact's draft along if nothing explicitly excludes it), and ordinary contacts' drafts survive instead of being needlessly destroyed. It also mirrors §S7's actual defense-in-depth property: even if the day-to-day `setVisibility` purge hook (previous section) had a bug and let a sensitive contact's draft slip through earlier, activation independently re-checks every row against current sensitivity rather than trusting upstream logic already worked.

### Gap found: bulk classification (`saveClassification`) doesn't purge, unlike the single-contact toggle

`setVisibility(for:isSensitive:)` (`ContactManager+Classification.swift:73-90`) — the per-contact toggle — purges that contact's draft the moment it's marked sensitive (line 84). `saveClassification(safeIDs:)` (`:52-65`) — the bulk pass behind `ContactClassification.swift`'s "Save" button — does not; it only writes `visibleThroughDepth` and runs the group-membership cleanup. It already computes exactly the set this needs: `hiddenIdentifiers` (`:55-60`) is every contact this call is newly classifying hidden at the current depth — precisely the set `setVisibility` purges for, just batched.

Fix is mechanical, not a new mechanism: after the classification loop, before `modelContext.save()` (i.e. right where `setVisibility` sequences its own purge relative to its save), purge each identifier in `hiddenIdentifiers`:

```swift
for identifier in hiddenIdentifiers {
    Message.Draft.purge(recipientID: identifier, in: self.modelContext)
}
```

Purging an identifier that was *already* hidden before this save (also present in `hiddenIdentifiers`, since the set isn't restricted to newly-hidden ones) is a harmless no-op — `find` won't match a row that isn't there. No change to `Message.Draft` itself; this only closes a gap in one caller.

### Considered and rejected: allowing drafts for sensitive contacts, backstopped by activation/duress purging alone

Revisited whether the Option E gate (§ above, "Sensitivity gate") could be dropped — save sensitive contacts' drafts too, and rely on the purge passes to clean them up before anyone under coercion could reach them. Doesn't hold up:

- **Activation (previous section) purges at layer *creation*, not at layer *entry*.** The canonical DB key only rotates when a duress layer is created or changed via Settings. A contact classified sensitive between one activation and the next — which could be indefinitely long, or the layer may never be touched again — would have its draft sit in the main store under the *same key* used for everything visible at that depth for that entire window. Anyone who reaches that depth, coerced or not, already holds the key that opens it.
- **Tier 1 has no activation event at all.** A contact can be marked sensitive via `ContactClassification.swift`'s "Save" flow with Secure Mode never turned on. There is no `activateSecureMode` call to hook a purge into for these installs, ever — "purge on duress" has nothing to attach to.
- **The gap directly above (`saveClassification` not purging) would have been silently load-bearing** for exactly this scenario — mark several contacts sensitive in bulk while a draft already exists, and today nothing purges it.

Conclusion: the sensitivity gate itself stays, on the evidence available at the time. Revisited below ("Explored: universal chaff-backed drafts") once a substantially different mechanism was on the table — not because this conclusion was wrong for what it evaluated (dropping the gate with *no* other change), but because it didn't yet have a chaff-based alternative to weigh against. What follows here (duress-entry purge, previous gap fix) is worth doing on its own merits regardless — defense in depth for drafts saved for contacts that later *become* sensitive.

### New hook: purge on duress-entry, not just duress-layer-creation

Today, entering an *already-created* duress PIN is a pure state transition — `Manager.Security.verify(_:)` (`Manager+Security.swift:841-882`) returns `.duress`, and `applyVerifyState(for:)` (`:927`) does `currentDepth += 1`. No key rotation, no draft purge — the rekey/purge pass only ever runs once, at the moment that layer was *set up* (previous section). A contact classified sensitive after setup, with a draft saved before this proposal even ships (or under a lifted Option E gate, if that's ever revisited), would keep that draft indefinitely across any number of later duress-PIN entries.

Fix: run a purge pass at the same place `currentDepth` actually changes — inside `applyVerifyState(for:)`'s `.duress` case, after the increment, using `self.currentDepth` (the new, post-transition depth). `Manager.Security` already owns a private `modelContext` (`:108`) and the static `isVisible(_:atDepth:)` (`:1143`) needs nothing but a fetched `Contact.Profile` and a depth — no `ContactManager` dependency needs to be added to `Security` or plumbed into `PINEntry` (which today has neither in scope).

```swift
// inside Manager.Security, called from applyVerifyState's .duress case,
// after self.currentDepth += 1
private func purgeDraftsNotSafeAtCurrentDepth() {
    guard let key = try? Manager.Key().createHybridLocalEncryptionKey() else { return }
    let profiles = (try? self.modelContext.fetch(
        FetchDescriptor<Contact.Profile>(predicate: #Predicate { $0.deletionToken == nil })
    )) ?? []
    let allIdentifiers  = Set(profiles.map(\.identifier))
    let safeIdentifiers = Set(profiles.filter { Manager.Security.isVisible($0, atDepth: self.currentDepth) }.map(\.identifier))
    try? Message.Draft.reKeyOrPurgeAll(
        safeContactIdentifiers: safeIdentifiers, allContactIdentifiers: allIdentifiers,
        oldKey: key, newKey: key, in: self.modelContext
    )
}
```

Reuses `reKeyOrPurgeAll` unchanged rather than adding a new purge-only variant: no draft-row key rotation actually happens at duress entry (the canonical key is the same key at every depth, and only rotates at activation), so calling it with `oldKey == newKey` re-seals surviving rows under an identical key with a fresh nonce — a no-op in effect, not a new crypto path to review — while getting the exact same, already-reviewed survive/purge semantics (including "a draft addressed to a group always survives this pass," matching activation's behavior, since group membership sensitivity is handled separately via `purgeMembersFromDuressDepths`, not via this identifier set).

Runs on every `.duress` verify, not just the first: idempotent (a contact already purged has no row left to find), and cheap — bounded by draft count, the same bound `Message.Draft.find` already relies on elsewhere.

### Investigated: does `reKeyOrPurgeAll`'s `isKnownContact` check let an already-hidden contact's orphaned draft survive?

**Status: original hypothesis wrong; investigation found a different, real bug instead.**

The suspected shape: `reKeyOrPurgeAll` (`Message+Draft.swift:225-262`) treats `!isKnownContact` as automatically safe — meant to let group drafts through, since groups aren't `Contact.Profile` rows. The worry was that a contact already Tier-2-relocated *before* a given activation wouldn't appear in `allContactIdentifiers` (built from `contactManager.fetchAllContacts()`) either, so their orphaned draft would read as "not a known contact" and survive un-purged, same as a group.

**Doesn't happen — the premise was wrong.** `activateSecureMode` never removes a sensitive contact from the queryable store at all: "Sensitive contacts remain in the DB (not hard-deleted)... Depth-based visibility... controls what appears in the UI — not the key" (`Manager+Security.swift:469-472`). Every profile, safe or sensitive, gets re-encrypted under the staged key at every activation (`:475-478`), and `fetchAllContacts()` (`Contact+Manager.swift:393-397`) filters only on `deletionToken == nil` — no depth check. A sensitive contact, however deeply hidden, always comes back from that fetch and always lands in `allContactIdentifiers` on the next activation. There's no state where a still-a-contact identifier silently drops out of that set, so `isKnownContact` is correct for every genuinely-still-a-contact row.

**The real bug: ordinary contact deletion, not Tier 2 relocation.** `deleteContact(identifier:)` (`Contact+Manager.swift:435-449`) — the actual delete-a-contact flow, called from `Contact+Form.swift:177` and `ContactFormV2.swift:200` — sets `deletionToken`, purges the identifier from every group's membership, but never calls `Message.Draft.purge`. Once `deletionToken` is set, that identifier drops out of `fetchAllContacts()` and therefore out of `allContactIdentifiers` on the next activation — so `!isKnownContact` now reads true for them, and an orphaned draft for a genuinely deleted contact survives (gets re-keyed, not purged) indefinitely, exactly the shape of bug originally suspected, just triggered by deletion instead of relocation. Not yet fixed — the fix is mechanical (add a `Message.Draft.purge` call to `deleteContact`, matching the pattern already used by `setVisibility`/`saveClassification`), but out of scope for this investigation pass.

**Bigger, adjacent finding: this investigation disproved a security claim already documented and relied on elsewhere in this same file.** See the correction inline in "Key" above — the "Key" section's original point 1 claimed Tier 2 relocation makes a sensitive contact's per-contact key undeivable (`fetchContact(by:)` "fails"). It doesn't; `fetchContact(by:)` has no depth filter and the contact row is never removed. The design's actual safety doesn't depend on this — point 2 in that same section ("explicit deletion, not key rotation, is the actual erasure mechanism") was already carrying the real weight — but the documented defense-in-depth claim was wrong, and there is one fewer real backstop than believed: a sensitive contact's attachment key stays derivable forever, with no crypto-level fallback if a purge is ever missed (which is exactly what the `deleteContact` gap above demonstrates happening in practice).

### `deleteContact`'s draft-purge gap — fixed

**Status: implemented.**

Mechanical, matching the existing `setVisibility`/`saveClassification` pattern exactly:

```swift
func deleteContact(identifier: String) throws {
    guard let contact = try self.fetchContact(by: identifier) else {
        throw ContactManager.Errors.contactNotFound
    }

    let softDeleted = try self.fetchSoftDeletedContacts()
    if softDeleted.count >= 50, let victim = softDeleted.first {
        self.modelContext.delete(victim)
    }

    contact.deletionToken = try Data([1]).encrypt()
    Message.Draft.purge(recipientID: identifier, in: self.modelContext)
    try self.modelContext.save()
    self.security.checkpointStore()

    try self.forEachGroup { try $0.purgeMember(identifier) }
}
```

- Purge sequenced *before* `modelContext.save()`, same ordering as the two existing sites, so the `deletionToken` write and the draft's removal land in one transaction.
- `self.security.checkpointStore()` unconditionally after save — reuses the method already added for this exact staleness concern ("Closing the staleness gap" below); `ContactManager` already holds `self.security`, no new plumbing needed.
- No attachment-specific handling needed — `Message.Draft.purge` → `delete(_:in:)` already removes the attachment folder alongside the row.

**Two things explicitly out of scope for this fix, named rather than silently dropped:**

1. **Existing orphaned drafts from past deletions aren't retroactively cleaned up.** This only stops new orphans from being created going forward. `activateSecureMode`'s own `reKeyOrPurgeAll` doesn't incidentally fix old ones either — confirmed: `!isKnownContact` reads true for an already-deleted identifier, so it "survives" (gets re-keyed, not purged) on every future activation, perpetuating rather than cleaning up the orphan. A backfill for drafts that are already orphaned today would be a separate, deliberate step.
2. **A more complete alternative exists, touching `reKeyOrPurgeAll` itself instead.** `!isKnownContact` is really trying to mean "this is a group, not a contact" — but it collapses that together with "this identifier used to be a contact and was deleted," treating both the same way. Checking against a known-groups set too, and purging only genuine unknowns, would fix both the forward case *and* retroactively clean up existing orphans on the next activation, without needing item 1's separate migration. Not pursued here — it's a bigger, riskier change to a Critical-severity operation (Secure Mode activation) than the narrow `deleteContact` fix above, worth its own decision rather than bundling in by default.

### Item 2's fix: replace `!isKnownContact` with an explicit group check — implemented

**Status: implemented.**

The fix is a net simplification, not just an addition. Today's survive check (`Message+Draft.swift:242-243`):

```swift
let isKnownContact = allContactIdentifiers.contains(recipientID)
let survives = !isKnownContact || safeContactIdentifiers.contains(recipientID)
```

`allContactIdentifiers` is used for nothing else anywhere in the function — its only job is computing `isKnownContact`, which is the flawed part. Replacing it with an explicit, positive check removes that parameter entirely rather than adding a third one alongside it:

```swift
let survives = allGroupIdentifiers.contains(recipientID) || safeContactIdentifiers.contains(recipientID)
```

Purge everything that isn't affirmatively a known group or a safe contact — no more negative heuristic standing in for "is a group." Confirmed via `ComposeViewModel.recipientIDString` that contacts and groups (`.contact(String)` / `.group(UUID)`, the latter as `groupID.uuidString`) are the only two recipient shapes a draft can have, so nothing else needs accounting for.

**Building `allGroupIdentifiers` is simpler than expected — the fork flagged last turn resolves cleanly.** `Group.readID()` (`Group+Model.swift:115-120`) decrypts `encryptedID` with the same shared canonical key everything else at this tier uses, no group-specific key material involved. Both call sites can build the set with a small, local, unshared fetch:

```swift
let allGroupIdentifiers = Set(
    ((try? modelContext.fetch(FetchDescriptor<Group>())) ?? [])
        .compactMap { $0.readID()?.uuidString }
)
```

- **`activateSecureMode`** (`Manager+Security.swift:404-511`) already holds `contactManager`; add this fetch alongside the existing `allProfiles`/`safeProfiles` computation in Step 4, pass it through to `reKeyOrPurgeAll`.
- **`purgeDraftsNotSafeAtCurrentDepth`** (inside `Manager.Security`) — last turn I flagged a fork here (direct fetch vs. threading `ContactManager` through `PINEntry`, which doesn't have it in scope today). Resolved: `Group` is a plain SwiftData model in the same store, and `Security` already holds `self.modelContext` — a direct `FetchDescriptor<Group>()` fetch needs no new dependency and no `PINEntry` plumbing at all.

Two identical small fetch snippets, one per call site, not factored into a shared helper — consistent with how this codebase already tolerates `walCheckpoint`'s own SQLite pragma helper being duplicated between `OccultaApp.swift` and `Manager+Security.swift` rather than shared.

**A side effect worth naming, not a new risk:** any recipientID that matches neither a known group nor a safe contact — not just a deleted contact, but any genuinely unrecognized or corrupt value — now gets purged instead of surviving. That's tightening toward the function's own already-stated philosophy ("fail-safe to gone"), not a behavior change introducing new risk.

**Confirms item 1 becomes unnecessary if this ships:** the very next `activateSecureMode` or duress-PIN entry after this fix lands would correctly purge every already-orphaned draft too, with no separate backfill migration needed.

**Testing note, given this touches a Critical-severity operation:** the whole drafts feature already has zero automated test coverage (`Manager.Key()` is hardcoded, not injectable via `KeyManagerProtocol`, requiring real Secure Enclave hardware) — this change would need real-device manual verification (delete a contact with an active draft, then activate/duress-enter and confirm the draft is gone; create a group draft and confirm it survives) rather than a unit test, same limitation as everything else in this feature.

### Closing the staleness gap: forced WAL checkpoint after every draft purge

**Status: implemented.**

Three call sites purge `Message.Draft` rows today; only one of them cleans up after itself the way `activateSecureMode` already does.

- `setVisibility(for:isSensitive:)` (`ContactManager+Classification.swift:73-90`) — purges the one contact's draft, pre-existing, never had this.
- `saveClassification(safeIDs:)` (`:52-65`) — bulk purge added earlier this session.
- `Manager.Security.purgeDraftsNotSafeAtCurrentDepth()` (`Manager+Security.swift`, called from `applyVerifyState`'s `.duress` case) — added earlier this session.
- `activateSecureMode` (`Manager+Security.swift:524-529`) — already forces `PRAGMA wal_checkpoint(TRUNCATE)` right after its commit. Not touched here.

The gap all three share: `PRAGMA secure_delete = ON` (`OccultaApp.swift:128-151`) zeroes a page's content the instant it's freed by a write, but only for *that* write. If the row's original `INSERT` landed in a WAL frame that hasn't been checkpointed yet, that earlier frame — holding the real, pre-purge ciphertext — can still be sitting in the WAL file, recoverable, regardless of how cleanly the purge itself deletes the row. None of these three call sites rotates any key either (only activation does), so a recovered stale frame stays decryptable by whoever holds today's still-live canonical key.

**Fix:** add one small method to `Manager.Security`, reusing its existing private `storeURL` and `walCheckpoint(at:)` (`:1234-1239`) rather than a fourth copy of the same four-line SQLite pragma call (a third copy already exists between `OccultaApp.swift` and `Manager+Security.swift` itself; this codebase already tolerates that duplication for this exact helper):

```swift
// Manager.Security — internal, not private: ContactManager already holds
// a `security: Manager.Security` reference (Contact+Manager.swift:57, 64)
// and needs to reach this from its own purge call sites.
func checkpointStore() {
    guard let url = self.storeURL else { return }
    Self.walCheckpoint(at: url)
}
```

Call it from all three sites — `setVisibility` and `saveClassification` via `self.security.checkpointStore()` (no new plumbing needed; `ContactManager` already holds the reference), `purgeDraftsNotSafeAtCurrentDepth` via `self.checkpointStore()` directly, since it already runs inside `Manager.Security`.

**Must run unconditionally, every call, not only when a purge actually happened.** This is the same principle `cleanUpGroupDuressMembership` already applies to its own ciphertext refresh (see its doc comment, "a classification save has to produce the identical observable footprint... no matter the depth or outcome — skipping the refresh whenever no real purge happens would itself be a keyless, forensically-visible signal"). A checkpoint that only fires when something was purged turns *checkpoint timing itself* into the exact kind of differential signal this whole fix exists to remove. `purgeDraftsNotSafeAtCurrentDepth` already satisfies this — it runs on every `.duress` verify regardless of outcome. `setVisibility`/`saveClassification` need the same discipline: call `checkpointStore()` on every invocation, whether or not `isSensitive`/`hiddenIdentifiers` ends up empty.

Cost is a non-issue — these are infrequent, deliberate user actions (a Settings toggle, a duress-PIN entry), not a hot path; `activateSecureMode` already pays this same cost unconditionally today.

### Explored: universal chaff-backed drafts as an alternative to the sensitivity gate

**Status: decided — building this.** A candidate that would let every contact — safe or sensitive — get real draft persistence, evaluated in depth and now committed to, weighed explicitly against leaving the sensitivity gate as-is: the gate keeps sensitive contacts at the safest achievable state (zero persistence, nothing to find) at the cost of the convenience of draft persistence for them; chaff trades that safety margin for the convenience, at real, permanent, accepted residual risk ("The honest ceiling," below) and a large engineering cost. Both open design parameters are now resolved (below) — implementation is deferred to a future pass, tracked as the step sequence in the session notes, not started yet.

**Reframing.** "Forensic tell" splits into two independent things that need different fixes:
- *Existence tell* — a row appearing or disappearing correlated with a classification or duress event.
- *Content tell* — the row existing but being decryptable, by anyone holding the currently-live canonical key, to reveal who it's for and what it says.

The purge hooks above are the best available answer to the existence tell *within* a delete-based model, but delete is never actually "as if it never existed" — see "Closing the staleness gap" above: a stale, un-checkpointed WAL frame can still hold recoverable, decryptable pre-purge ciphertext regardless of how cleanly the row itself gets deleted.

**The chaff mechanism.** Give every contact and group a draft row from the moment they're addressable — not gated on typing activity, and never deleted. Real typing overwrites the row FAKE→REAL through the normal debounced save. Anything that would otherwise *purge* a real draft (reclassification, duress entry, send) instead overwrites it REAL→FAKE with freshly generated filler. There is never a create or delete event tied to a classification boundary — the row's lifecycle is identical for every contact, always, so there is nothing for a reclassification or duress-entry moment to leak by its mere occurrence.

This dominates delete-based purging on the existence axis specifically, and folds in cleanly with the per-contact-key content-sealing idea from the same brainstorm (seal `encryptedContent`, real or fake, under the recipient's own key rather than the canonical one — real or Tier 2-relocated protection then applies automatically to whichever content currently occupies the row, with no special-casing for fake vs. real anywhere).

Two things it does *not* solve for free:

1. **Staleness on the swap.** REAL→FAKE is still an `UPDATE`, not a delete, but the same un-checkpointed-WAL-frame gap applies identically — the just-replaced real content can still be recoverable until a checkpoint runs. Any implementation of this needs the same `PRAGMA wal_checkpoint(TRUNCATE)` immediately after a REAL→FAKE swap that activation already does after its own commit.
2. **Content plausibility becomes the hard problem**, addressed below.

**Content generation — what was ruled out, and why.**

- *Deterministically deriving each fake from key material (e.g. HKDF off the per-contact key)* — rejected. Anyone who holds the key needed to decrypt a row can recompute whatever deterministically generated its fake and diff the two: exact match → fake, mismatch → real. That's not a soft tell, it's a perfect oracle, strictly worse than no per-contact variation at all. Fakes must be generated with **true, one-shot randomness** (`SecRandomCopyBytes`) and the *result* persisted through the same `DraftStore.save` path real content uses — once written there is no seed left over anywhere to recompute against, exactly as unrecoverable as what a real, never-sent draft's origin is.
- *Reusing `Assets/eff_large_wordlist.txt`* (already bundled for diceware passphrases, `Passphrase+Manager.swift`) — rejected on two grounds: diceware words are chosen to be mutually *unrelated* for entropy, so concatenating them reads as word-salad, not typed prose; and this exact list already carries a known security meaning elsewhere in the app, so recognizing it inside a "draft" is a direct, specific correlation between the deception mechanism and the app's own security tooling — sharper and more damning than generic corpus-fingerprinting risk.
- *Bundling a dedicated small on-device model* — see "Considered and rejected: on-device models for content generation" below, its own subsection given how much ground it covers.
- **Chosen direction: source vocabulary from the OS itself, not from anything Occulta bundles.** `UITextChecker.completions(forPartialWordRange:in:language:)` returns real words from the device's own active-language system dictionary given a random prefix — nothing Occulta-specific ships as a data asset, and content automatically localizes to whatever language(s) the device's own keyboard is configured for. A small hardcoded set of universal connector words ("hey", "so", "ok") is still needed as template glue, since the API is prefix-based, not "give me a greeting" — but these are common enough to carry no real fingerprint value on their own, unlike a curated corpus. Needs a retry-with-a-different-prefix fallback since some prefixes (e.g. "qz") return no completions.
- **Never derive prefix or word selection from the contact's own identity/name/profile fields.** Doing so would inject a real, decryptable correlation between actual identity and "fake" content — the opposite of the goal, and a more direct leak than anything else considered here.

### Considered and rejected: on-device models for content generation

Two distinct options here, evaluated separately, both ultimately passed over in favor of the OS-dictionary approach above.

**Option: Apple's on-device `FoundationModels` framework.** Since iOS 18.1/Apple Intelligence, Apple ships an on-device generative model apps can call directly (`SystemLanguageModel`/`LanguageModelSession`) — fully local, no network call, which fits this app's zero-server architecture rather than compromising it. The model itself is compact (on the order of ~3B parameters, quantized for the Neural Engine) and purpose-built for short-form tasks — summarization, tone rewriting, structured/"Generable" typed output — not open-ended long-form chat, which is actually a good fit for generating a short plausible fragment.

Two things rule it out as the *primary* mechanism, not just weaken it:

- **Hardware floor mismatch.** Apple Intelligence requires A17 Pro or later silicon. This app's own stated minimum device (`CLAUDE.md`: "physical iPhone 11+ (U1 chip required for NearbyInteraction)") is A13 Bionic — several generations below. iPhone 11 through 15 base/15 Plus, plus any eligible device where the user simply hasn't enabled Apple Intelligence, all fall outside it. Availability is a runtime enum apps must check (`.available` vs. `.unavailable(.deviceNotEligible)`/`.unavailable(.appleIntelligenceNotEnabled)`/`.unavailable(.modelNotReady)`) — unavailability is Apple's own designed-for, expected outcome, not an edge case to shrug off. Given the mismatch with this app's floor, it could only ever be an enhancement on the subset of eligible, enabled devices, with the OS-dictionary approach as the mandatory primary path regardless.
- **A sharper danger than a bundled corpus: the prompt itself.** Whatever instruction string drives the model ships as a literal string in the compiled binary (unlike Swift source comments, which never ship — this is specifically about runtime string literals and bundled resources). A prompt reading something like "write a casual abandoned text message" sitting in the binary's strings section isn't ambiguous evidence the way a word list is — it's a direct confession of anti-forensic intent. Any implementation would need the prompt to read as something else entirely if it were ever extracted, or this backfires worse than not having the feature.

**Option: bundling a dedicated small on-device model of Occulta's own**, running via CoreML — sidesteps the hardware floor entirely (works on anything meeting this app's own minimum, since it's just local inference, no Apple Intelligence gate) but reopens the corpus-presence problem one level up in a different shape: a bundled model file with no corresponding *visible* app feature has no innocent explanation for its own existence in the IPA. A CoreML model isn't inherently suspicious — plenty of apps ship them for mundane reasons (Vision features, filters) — what's revealing is a model with no matching UI feature anywhere in the app. Mitigated only by right-sizing it (a tiny character/word-level generator, in the low single-digit-MB range — closer to a well-built Markov model than a modern "small LLM," which is more capability, and more footprint, than generating a short non-templated fragment actually needs) and, more durably, by giving it a genuine user-visible secondary purpose (e.g. predictive-text suggestions in compose) so its presence has an honest cover story independent of the chaff use.

**Net comparison of all three generation sources considered:** `FoundationModels` where eligible gives the best content quality and zero bundle footprint, at the cost of the worst device coverage. A bundled tiny model gives full device coverage at a small bundle-footprint cost that needs a genuine secondary use case to justify. The OS-dictionary approach — the one actually chosen — gives full device coverage and zero bundle footprint, at the cost of weaker content quality (more visibly templated) than either model-based option. Training/sourcing a bundled model's weights is a modest, tractable undertaking on its own (a small char-level generator trained on a generic public corpus, converted via `coremltools`) — not comparable in cost to building a real LLM — so this isn't ruled out by infeasibility, just by the OS-dictionary option already covering the same ground with less exposure.

**Shape of the generated content.** Skew heavily toward incomplete fragments ("hey did you" with no ending), not complete sentences — a draft is disproportionately an abandoned partial thought in reality, which is simultaneously *more* plausible and *easier* to generate convincingly than forcing grammatical coherence out of independently-drawn dictionary words.

**Decided: template slot design.** Two slots, assembled in order, plus a trailing style roll:
- **Connector slot** (60% chance of appearing, first when present): one word drawn from a small hardcoded set of common conversational openers — "hey", "so", "ok", "yeah", "sorry", "wait", "actually", "look", "listen", "um". Small and generic enough to carry no real fingerprint value on its own (§ above).
- **Dictionary-word slot**: 1-3 words via `UITextChecker.completions`, count itself randomly weighted toward fewer (1 word ~50%, 2 words ~35%, 3 words ~15%), each word an independent random-prefix draw with its own retry-on-empty fallback — never sharing a prefix draw across words in the same fragment.
- **Trailing style**, rolled independently: no punctuation (~60%, the default — matches an abandoned, unfinished thought), a trailing ellipsis (~20%), or truncating the last dictionary word to a partial prefix mid-type (~20%, mimicking someone who stopped typing mid-word).
- **Casing**: lowercase first letter by default (~85%, matching casual typing norms), occasional capital first letter (~15%).

Same caveat as the size parameters directly above: these percentages are a considered starting point, not calibrated against real data — there's nothing to calibrate against in a zero-telemetry app. Revisit empirically if this ships.

**Size — corrected: continuous random padding, not fixed buckets.** An earlier version of this section proposed padding every row up to one of a small set of fixed sizes (§K1's fixed-width-encoding precedent, illustratively 512B/2KB/8KB/32KB — the top value chosen to match `activateSecureMode`'s existing 32KB blob-slot ceiling). **Wrong, and worse than doing nothing:** AES-GCM is length-preserving, so ciphertext byte-length is visible to anyone looking at the raw stored bytes, no key required — that part of the reasoning was right. But naturally-typed human content essentially never produces exact size collisions across many independent rows; snapping every row to one of 4 shared values creates massive, artificial clustering that a plain `SELECT LENGTH(encryptedContent), COUNT(*) FROM drafts GROUP BY LENGTH` surfaces immediately, no decryption needed. That's not a neutral "detecting that padding exists" observation — it's a direct, specific trace that deliberate anti-forensic countermeasures are running underneath the app, exactly the category of thing this file's own opening principle warns against ("We must be forensic trace clean... We should not be leaving traces that we are hiding something").

Fixed: draw a fresh, independent random target length for *every* write — real or fake — from a continuous distribution shaped like organic message lengths (skewed toward short, a long tail out to roughly the same 32KB ceiling), then pad up to that specific target. Redraw it on every rewrite, never reuse a prior target for the same row. This keeps everything fixed buckets were for — true content length still masked, real and fake content still drawn from the same size-generating process, so post-encryption size still carries no real/fake signal — without the collision problem: with a wide, continuous, independently-random target per row, two rows landing on the exact same byte count is about as unlikely as it would be for genuinely organic data. Nothing left to `GROUP BY` and notice.

**Decided: distribution parameters.** Floor 512 bytes, ceiling 32,768 bytes (the same existing precedent as before), drawn via `target = floor + pow(u, 4) * (ceiling - floor)` where `u` is uniform random in `[0, 1)`. `pow(u, 4)` concentrates most draws near the floor while still occasionally reaching the ceiling — median target lands around ~2.3KB, with a long tail out to 32KB. The floor is set comfortably above the realistic minimum payload size (JSON structure for an empty `draftText`/`basket`/`wasThreadMode`/`padding` plus 28 bytes of AES-GCM overhead lands around 250-280 bytes), so the draw only rarely needs adjusting upward — but the rule is unconditional regardless: if actual (real, un-padded) content size ever exceeds the drawn target, use `max(drawnTarget, actualSize)` — padding can only ever add, never subtract. Stated plainly: these parameters are a considered starting point, not a calibrated one — this app's zero-server, no-analytics architecture means there's no real telemetry on actual draft-length distributions to tune against, the same limitation already accepted for the fake-content template design below. Revisit empirically if this ships and real-world size distributions turn out to look different than assumed here.

**Write-cadence — resolved: reseal everything, uniformly, on `.active`, no background task.** A fake generated once and never touched again is conspicuously *still* next to a row that gets genuinely debounce-updated while someone actively types. Rather than a `BGTaskScheduler` job nudging a random subset on some independent schedule (rejected — opportunistic/throttled by iOS's own heuristics, real registration overhead, hard to test, and it doesn't actually need to exist separately from an event the app already has), tie it to `scenePhase` becoming `.active`: on every foreground transition, re-seal *every* `Message.Draft` row unconditionally, fake or real, touched-since-last-time or not. This doesn't approximate organic touch patterns statistically — it removes the differential outright. There's no such thing as "a row that's sat untouched for months" anymore, for anyone; the starkest, easiest-to-notice signal is gone by construction rather than papered over with randomization. It's also simpler to build than the background-job version: no candidate-selection logic, no scheduling, no separate battery budget — just a sweep on an event the app already reacts to.

Honest residual, not chased further: a contact actually being typed to *also* gets extra debounce-triggered writes clustered within that compose session, on top of the uniform per-open touch everyone gets — so write-*burstiness* (several rapid writes in a few minutes vs. exactly one touch per app-open) could still distinguish a genuinely active conversation from a swept-along fake, to a sufficiently close comparison. Accepted: this is a far finer signal than today's baseline, and matches the same "defeat bulk/statistical inspection, not exhaustive forensic timing analysis" bar already settled on elsewhere in this section.

**Concurrency with real debounced saves.** The resweep is a separate, batch-wide operation over every row directly via `ModelContext` — not an extension of the existing per-view `DraftStore` instances, which only exist while a specific compose screen is mounted and only track one `saveTask` for that screen's own recipient. If a compose screen for contact X is open at the exact moment `.active` fires, the resweep and that screen's own live debounced save could race on the same row. Fix: a small in-memory registry of "recipient IDs with a compose screen currently mounted" (each `ContactDetailV3`/`GroupDetailV3`/`ContactDetailV2`'s `.task`/`.onDisappear` registers and unregisters itself) — the resweep simply skips anyone in that set on a given pass. No persistence, no locking, removes the race by construction rather than detecting or recovering from it.

Explicitly ruled out as part of this: an `isFake: Bool` field on the sealed `Payload` to let the resweep (or anything else) cheaply tell real from fake. That would be a serious mistake, not a shortcut — anyone with the decryption key wouldn't need any content analysis at all, they'd just read the flag. "Is this fake" can only ever be in-memory, code-path knowledge (which function is currently running), never anything persisted in or derivable from the row itself.

**Scope call: text only.** Faking plausible binary attachments (matching real image/video size and structure) is a much larger surface for uncertain benefit, since most real drafts are probably text-only anyway — absence of an attachment isn't itself unusual. Leave out unless the real attachment rate turns out high enough to make its absence in every fake a statistical tell on its own.

**The honest ceiling.** None of this defeats a maximally resourced, target-specific adversary who both holds the live key *and* is willing to do manual linguistic forensics against a reverse-engineered generation scheme for one flagged individual — that ceiling is inherent to any offline, source-available, zero-server app and isn't specific to drafts (the same line was already drawn once, deliberately, in Option H above, for message history). What this design achieves is real: it eliminates the existence-tell and write-cadence-tell for bulk/automated inspection, which is the far more likely real-world threat shape, without pretending to win an unwinnable arms race against the narrower one.

**Decided: no per-contact-key content sealing.** Considered as an orthogonal, composable addition (§ above, "why switch to per-contact key" discussion) — the concrete gap that originally motivated it, missed purge-invocation sites, is now closed by the checkpoint-fix scoping, and its staleness benefit only ever covered content, not `encryptedRecipientID` (which needs that same checkpoint fix regardless of this decision). `Message.Draft` rows, real or fake, stay uniformly Tier 1 — sealed under the canonical local DB key, matching the original "Key" decision above and everything else at that tier. Moot as a result: the parallel per-group-key mechanism this would have required, since groups have no stable per-recipient key the way contacts do via `ContactManager.fileEncryptionKey(for:)`.

**Both previously-open design parameters are now resolved (above).** Nothing left to decide before implementation starts — only the build itself, deferred to a future pass. See the nine-step build sequence agreed on when this was decided (universal row creation, the padding mechanism, fake content generation, removing the live gate, converting all four purge sites to swap-not-delete, redirecting the checkpoint call, the uniform reseal-on-`.active` sweep with its concurrency guard, then manual on-device verification).

### Resolved: no biometric-gated key tier for drafts

Unlike the still-open Q-04 for full message history, drafts don't get the Vault's biometric-gated SE key tier. The point of a draft is frictionless resume of an in-progress composition — requiring Face ID to reopen one would defeat that, and the residual risk is already bounded by the sensitivity gate (nothing sensitive-contact-shaped is ever stored) and the activation-purge safety net. Decided, not left open.

### Resolved: excluded from backup

`Drafts/` gets `isExcludedFromBackup = true`, matching §B7's precedent for the Secure Mode blob. Accepted trade-off: drafts don't survive a backup-restore or device migration, in exchange for not exposing them if a device backup is ever examined. Decided, not left open.

### Resolved: UI — a "Draft" label on the contact row, replacing the fingerprint slot rather than adding to it

The only new UI surface this feature needs: a small indicator on a contact's row in `ContactsListV2` so a saved draft is discoverable (and trustworthy — otherwise nothing tells the user their unsent text really survived). No text preview — just the label, to avoid decrypting and displaying content in a list context. Everywhere else (the compose views themselves), a restored draft should look identical to having never left; no "recovering your draft..." banner, no new screen.

Checked the actual `ContactRowV2` implementation (`ContactsListV2.swift:218-274`) before designing this, rather than assuming a layout — good thing, since the obvious first guess (a job-title subtitle line) is wrong. The real subtitle row is `[verification-status dot] + [optional fingerprint hex text, shown only when a `showFingerprint` toggle is on]` (`:256-267`). That fingerprint text is a real, already-conditional occupant of the same line a draft label would want. Appending "Draft" unconditionally would let both render simultaneously when `showFingerprint` is true, cramping a single-line `HStack`.

Fix is precedence, not more space — the status dot always shows (compact, always-meaningful), but the second slot picks one of two occupants, draft taking priority:

```swift
if hasDraft {
    Text("Draft")
} else if self.showFingerprint, let fp = self.contact.fingerprintPreview {
    Text(fp)
}
```

They never render at the same time regardless of how `showFingerprint` is toggled.

---

All open items for drafts are now resolved. Nothing blocks moving this to implementation.

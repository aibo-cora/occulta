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
- **Tier 2 (strong).** Full Secure Mode duress activation (`activateSecureMode`, `Manager+Security.swift:404-445`) physically *removes* sensitive contacts from the queryable store and reseals them into a separate `LayerStore` blob under a Secure-Enclave-derived, depth-specific key (`layerStore.deriveKey(from: seKey)`, line 400). At a shallow depth those bytes genuinely don't exist in the queryable database — structural absence, not a filter.

**The per-contact "Private contact" toggle only gets Tier 1.** Any forensic risk discussed below already exists for contacts themselves, before message persistence adds anything.

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

### Content: a sealed `Basket`, not a bespoke encoding

A draft's text and attachments are bundled into the same `Basket` (`Occulta/Data Models/Transfers.swift:27-36`) already used for real sends — reusing the existing structure instead of inventing a separate draft format. Text and attachment *references* travel inside one sealed `Basket`, so there's only one thing to crypto-erase for the row's own content; attachment file *bytes* are a separate question, addressed below under "Key" and "Attachment storage."

Full reuse of `ContactManager.encryptBundle(for:)` (`Contact+Manager.swift:938-1073`) was considered and rejected: it requires a real `Contact.Profile` — `fetchContact(by:)`, prekey pop/forward-secrecy state, version resolution — all genuinely contact-specific. Making "self" work through that path means inventing a synthetic self-contact, which is exactly the complexity already avoided once for the Vault feature (chose `VaultEntry.note` over a synthetic "You" contact). Not worth reopening for drafts.

What *is* reusable: the sealing primitive underneath is already generic. `Crypto+Manager+GroupEncrypt.swift:122-165` generates a random session key and does a plain `AES.GCM.seal(payloadData, using: sessionKey, ...)`, with recipient-specific ECDH key-wrapping happening as a separate step afterward — the seal itself doesn't know or care about contacts. The decrypt side already has the shortcut this needs: `open(_:using: SymmetricKey)` (`Crypto+Manager+ForwardSecrecy.swift:100`) takes a raw symmetric key directly, no contact lookup. The encrypt side has no counterpart yet — add a small `seal(sealedPayload:using: SymmetricKey)` mirroring it, calling the same already-generic internals. Small addition, not a restructuring.

### Key: the canonical local DB key for the row; the existing per-contact key for attachment files

The `Message.Draft` row itself (`encryptedRecipientID`, `encryptedContent`) is sealed under the canonical local DB key. Originally scoped as a two-layer scheme (a static self-key-agreement secret wrapping a separate, rotatable draft key) specifically so Secure Mode activation could destroy the wrapping key and crypto-erase every draft. Unnecessary: **the canonical local DB key already rotates on activation** — §S1 documents this as an existing, audited, Critical-severity mechanism ("the local DB key is `ECDH(ourSEKey_localDB, G)`... rotation... is the core reason the DB key rotates on activation," old key deleted after commit). Encrypting the row directly under this same canonical key gets the identical crypto-erasure guarantee for free, through a mechanism that's already built and already trusted, instead of a parallel one that needed auditing from scratch. It's also the more consistent choice given a decision already made below: drafts get Tier 1, not the Vault's biometric-gated tier — the canonical DB key *is* Tier 1, the same key already protecting `Contact.Profile.visibleThroughDepth` and everything else at that level.

**Attachment *files* stay under the existing per-contact key** (`ContactManager.fileEncryptionKey(for:)`) already protecting them during active composition — they are *not* re-sealed under the canonical key. This isn't the rejected two-layer scheme above (a *new*, purpose-built rotatable key wrapping something static) — it's simpler: reusing a key and a manager (`AttachmentManager`) that already exist and are already used for this exact content at every other stage of a message's life (composing, sending, displaying a sent thread). Re-sealing under the canonical key at save time was considered and rejected: it would cost a decrypt/re-encrypt round-trip per attachment, on top of the encrypt/decrypt `AttachmentManager` already does at send time, for no security benefit — see below for why.

Two things make the per-contact key safe here rather than a gap:

1. **`fileEncryptionKey(for:)` requires the contact's live `Contact.Profile` row** (`Contact+Manager.swift:589-600` — reads `contact.contactPublicKeys?.last?.material`). When a contact becomes sensitive-at-this-layer during Secure Mode activation, their profile is physically relocated out of the queryable store into the `LayerStore` blob (D-05's Tier 2). `fetchContact(by:)` then fails, and `fileEncryptionKey(for:)` throws — the per-contact key becomes undeirvable as a direct consequence of contact relocation that's already built and audited, no extra rotation needed for attachments specifically. For contacts who *survive* activation (profile stays, re-encrypted under the staged key via `reencryptAllFields`), their key material survives too, so the same per-contact key keeps deriving correctly — exactly the behavior wanted for a surviving draft's attachments.
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

### Lifecycle: when a draft is actually written, read, and cleared

- **Persisted lazily**, not on every keystroke: at the same point `ComposeViewModel.cleanup()` currently fires (`.onDisappear`, backgrounding) — replacing "delete the attachment" with "run the sensitivity gate, then persist if not sensitive."
- **Resumed on open**: when a compose view opens for a recipient, check for an existing `Message.Draft`, decrypt it, and load its `Basket` back into `draftText`/`messages` before the user starts typing.
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

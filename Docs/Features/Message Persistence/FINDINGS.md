# Message Persistence — Design Findings

**Status:** Exploratory — no SPEC.md yet, not scoped for a release
**Context:** Design discussion, 2026-07-14. Originates from the friction report's Sweep 2 (`Friction/USER_ENGAGEMENT_FRICTION.md`, C3/H1/H2) — "one persisted store + one inbox UI + one notification hook" for drafts, message history, and inbound delivery. Captures the security investigation done before any schema or code is written, so the reasoning isn't lost before this gets formally scoped.

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

## Prerequisite for implementation

Q-01 is resolved (Option E + B). Q-04 (SE-key tier) still needs an answer before the `Contact.Message` schema extension is written — it changes both the field shape and the UX. Q-02's purge-vs-retag sub-question should be settled before shipping, since it determines part of the `setVisibility` extension's behavior. Q-03 should be written down as a known limitation in whatever SPEC.md eventually follows this doc, not left implicit. D-08 (preserve §C2's unconditional duress-discard exactly) and D-09 (stamp new messages at insert time from current contact sensitivity) are not optional — either being missed breaks the existing security model rather than just leaving a gap in the new one. Option E's persistence gate (§C1-style suppression extended to normal-unlock processing) is now equally non-optional alongside them.

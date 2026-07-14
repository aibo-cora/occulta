# Message Persistence — Design Findings

**Status:** Exploratory — no SPEC.md yet, not scoped for a release
**Context:** Design discussion, 2026-07-14. Originates from the friction report's Sweep 2 (`Friction/USER_ENGAGEMENT_FRICTION.md`, C3/H1/H2) — "one persisted store + one inbox UI + one notification hook" for drafts, message history, and inbound delivery. Captures the security investigation done before any schema or code is written, so the reasoning isn't lost before this gets formally scoped.

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

### D-06 · Confirmed gap: nothing retroactively re-tags related data when sensitivity changes

`setVisibility` only touches the `Contact.Profile` row and triggers `cleanUpGroupDuressMembership` (`ContactManager+Classification.swift:84, 114-123`), which only touches `Group` rows. It never reaches `Vault+Manager.swift` or `CustodyShard`/`ShardRecord`. `CustodyShard` rows (`Vault+Model.swift:78-88`) are keyed by `contactIdentifier: String`, and `VaultEntry.visibleThroughDepth` is stamped once, at creation time (`Vault+Manager.swift:213`), from whatever `currentDepth` was *then*. **If a contact is used normally, generating vault entries or shard custody, and is later marked sensitive, those existing records keep their original visibility stamp and are not retroactively hidden.** This is a real, currently-shipping gap, independent of anything being added for messages — and it will affect a new `Contact.Message` table the same way if not addressed.

### D-07 · Inconsistent linkage conventions already exist across the codebase

`CustodyShard`'s `ShardRecord.contactIdentifier` (`Vault+Model.swift:80-81`) uses the raw `Contact.Profile.identifier` directly — explicitly documented as deliberate ("a stable SwiftData UUID, not derived from the key fingerprint"). The dormant `Contact.Message` model takes the opposite approach in its own doc comments: `recipients` as "hash of their public key," `origin` as "encrypted ID of the owner" — not the raw identifier. Two different linkage philosophies already exist in the codebase for referencing a contact from a related record; message persistence has to pick one rather than inherit an assumption from either.

---

## Design Decisions

**Drafts will be self-encrypted, not stored plaintext or File-Protection-only.** Reuses the self key-agreement mechanism scoped for the Vault's encrypt-to-self feature (`privateKey.sharedSecretFromKeyAgreement(with: publicKey)`, deriving a stable symmetric key from one's own SE identity key) rather than introducing a plaintext exception or relying solely on iOS Data Protection. Keeps "plaintext never touches SwiftData" true without exception, matching `VaultManager`'s stated rule verbatim. Attachments stay encrypted on disk through drafting exactly the way they already are during active composition (`AttachmentManager.encrypt`/`streamingEncryptor`, per `ComposeViewModel.swift`) — no weaker-protection window while a draft sits unsent.

---

## Open Questions (Unresolved)

### Q-01 · Message-to-contact linkage: raw identifier or derived?

Following the `CustodyShard` convention (raw `Contact.Profile.identifier`) is simpler to query (`#Predicate` matches directly) and consistent with existing precedent. A derived/hashed linkage (closer to `Contact.Message`'s own aspirational doc comments) is more guarded but requires computing the hash before every query — no plain predicate match. Messages are higher-volume and more revealing than a one-time shard record, which argues for the more guarded approach even though it breaks from the shard-record convention. Not yet decided.

### Q-02 · Retroactive re-tagging is undesigned

D-06's gap needs a fix — `setVisibility` should re-stamp existing related rows (messages, and ideally `VaultEntry`/`CustodyShard` too, since they have the identical gap today) when a contact's sensitivity changes, not just apply going forward. This closes a pre-existing vulnerability, not just a hole in the new feature. No design done yet for how the re-stamp walks related tables or what it costs to do atomically.

### Q-03 · Tier 2 protection for messages is explicitly out of scope for this pass

Even with D-06 fixed and every `Contact.Message` row correctly Tier-1-tagged, rows still physically exist in the database regardless of depth — true structural hiding (Tier 2, LayerStore-style relocation) is a separate, larger security initiative that today only covers full Secure Mode contact activation, not vault entries or the lightweight per-contact toggle. This should be named as a known, explicit residual limitation rather than silently left unaddressed or accidentally implied as solved by Sweep 2.

---

## Prerequisite for implementation

Q-01 (linkage field) needs an answer before the `Contact.Message` schema extension is written — it changes the field shape and query pattern. Q-02 (retroactive re-tagging) should be at least designed, even if implemented as a fast-follow, before shipping persisted messages tied to a sensitivity toggle that can currently orphan visibility state. Q-03 should be written down as a known limitation in whatever SPEC.md eventually follows this doc, not left implicit.

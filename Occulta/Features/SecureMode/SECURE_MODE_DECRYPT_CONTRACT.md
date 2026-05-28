# Secure Mode — Decryption-Failure Contract

A contact or vault entry that fails to decrypt must be treated identically to one that never existed: excluded from lists, invisible to search, returning `nil` from any identifier lookup. No placeholder, no empty row, no timing difference.

**Enforcement point:** `Manager.Security.isDisplayable(_:)` / `isVisible(_:atDepth:)`. Every display path must pass contacts through this gate. Call sites that receive contacts already filtered by this gate are covered by inheritance; call sites that do their own fetching must filter explicitly.

---

## Contact Display Paths

| Call site | How it fetches | Guarded by | Status |
|---|---|---|---|
| `ContactsListV2.visibleContacts` | `@Query` | `security.isDisplayable($0)` — filters all contacts at current depth | ✅ |
| `ContactDetailV2` | receives `Contact.Profile?` from `@Query` in parent | Parent list already filtered | ✅ |
| `ContactsListV2` row cell | receives profile from `visibleContacts` | Already filtered | ✅ |
| `KeyExchange` | `@Query` filtered to single identifier | Operates on a contact the user navigated to from the filtered list | ✅ |
| `ContactClassification` (activation flow) | `@Query` all contacts | Activation runs before state transitions; no depth filtering needed | ✅ |
| `VaultGlobalTrustees` | `@Query` all contacts | Reads name for display only — empty string fallback acceptable; non-security context | ⚠️ acceptable |
| `Vault+ShardSetup` | `@Query` all contacts | Same as above | ⚠️ acceptable |
| `Vault+Tab` trustee display | receives contact from query | Same as above | ⚠️ acceptable |
| `IdentityChallenge+Coordinator` | fetches by identifier | Falls back to `"Unknown"` on empty name; no sensitive data exposed | ✅ |
| `IdentityChallenge+View` | receives contact from coordinator | Coordinator fallback covers it | ✅ |
| `PQmigration` | iterates all contacts | Debug name only — `#if DEBUG` context | ✅ |

---

## Share Extension Path

| Call site | How it fetches | Guarded by | Status |
|---|---|---|---|
| `ContactManager+ShareIndex._syncShareIndex` | `fetchAllContacts()` filtered by `shareIndexAllowedIDs` | In restricted mode: `shareIndexAllowedIDs` is populated from `safeContactIDs(atDepth:)` which calls `isVisible` — corrupted contacts excluded. In normal mode: `shareIndexAllowedIDs` is nil → all contacts used. A corrupted contact would appear in the share index with an empty display name (not a security issue — no sensitive data exposed, just a blank entry). | ⚠️ acceptable |

---

## Identifier Lookup Paths

| Call site | Contract |
|---|---|
| `isSafeContact(_ identifier:)` | Fetches by identifier; calls `isVisible` — returns `false` for corrupted contact | ✅ |
| `safeContactIDs(atDepth:)` | Fetches all; `isVisible` excludes corrupted contacts from returned set | ✅ |
| `ContactManager.fetchContact(by:)` | Returns `Contact.Profile?` — callers must not display if `isVisible` would fail; currently only used by `convertToMutableCopy` and key update paths (not display) | ✅ |

---

## `String.decrypt()` behaviour

`String.decrypt()` returns `""` on failure — it does not distinguish "field genuinely empty" from "field failed to decrypt." This is intentional: individual field fallback to empty string is acceptable in non-list contexts (detail views, debug logs). The contract is enforced at the list-entry level via `isDisplayable`, not at the individual-field level.

**Do not change `String.decrypt()` to throw or return `nil`.** The current signature is load-bearing across hundreds of call sites. The gate at `isDisplayable` is the correct enforcement layer.

---

## Timing

`String.decrypt()` on AES-GCM authentication failure returns immediately on tag mismatch — potentially faster than a successful decrypt. Under Design A (all contacts readable in normal operation) this never fires in practice. Under a future Design B upgrade, timing normalisation should be considered: add a fixed minimum duration to the decrypt-fail path to equalise timing against the success path. Not implemented; document here as a pre-Design-B requirement.

---

## Update policy

This file must be updated on every PR that:
- Adds a new display path for `Contact.Profile` fields
- Adds a new fetch in the Share Extension
- Changes `isVisible` / `isDisplayable` logic
- Adds a new process boundary (notifications, widgets, app clips)

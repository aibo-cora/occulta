# Contacts list hangs 0.7–2 s on every redraw: uncached key derivation inside `ContactsV2.body`

**Status: fixed on `v2.1.0/contact-list-performance` (uncommitted when this was written), measured on device: 23 hangs and 23.6 s down to none.** The fourth instance of the pattern in `Vault-Shard-Setup-Severe-Hang-From-Uncached-Per-Row-Vault-Key-Derivation.md` and `Vault-Backup-And-Shard-Recovery-Uncached-Key-Derivation.md`: each `String.decrypt()` / `Data.decrypt()` builds a `Manager.Crypto()` and derives the local DB key afresh, and the contact screens call it per contact, per field, per `body` pass.

## Symptom

Moving between views, tapping, and typing in the contacts search field take 0.7–2 s to respond.

## Measurement

Time Profiler, Release build of `v2.1.0/contact-list-performance` (branch of `release/v2.1.0`), iPhone 15 Pro, iOS 26.7.1, one 2-minute session on a real store: contacts list scroll, open and close a contact 3–4 times, search typing, compose typing.

- **23 main-thread hangs, 23.6 s in total.** One Severe Hang (2.08 s); the rest 0.69–1.93 s. A run of ~0.7 s hangs about a second apart, which fits a redraw per search keystroke.
- **86% of the time inside the hangs (20.7 of 24.0 s) is under `Manager.Key.enclaveBoundKey`.** 19.4 s of it is under `ContactsV2.body`; the detail view is a small share.
- **Only ~7% of hang time is CPU.** The rest is the main thread blocked, in the calls the derivation makes: `SecItemCopyMatching` (Keychain reads of the tier secret, the tier PQ record and the Enclave key reference) about 10.7 s, ML-KEM `decapsulate` about 6.7 s, the Enclave ECDH about 1.8 s. Time Profiler does not sample a blocked thread, so this wait is attributed from the gap after the last running sample (an approximation, not a wait-state trace).
- Inside `ContactsV2.body`, the callers are `ContactListFilter.visibleContacts` / `isVisible` (read about four times per pass), the sort comparator in `sortedContacts` (decrypts family and given name on both sides of every comparison), `statusAndCard`, and the row's name, thumbnail and `pairingCapabilities` reads.

The ~2 ms per derivation in the sibling doc is the legacy path. The Enclave-bound path (tier secret and PQ record from the Keychain, then ML-KEM decapsulation) is what ships since Bug 171, and costs several times that.

## Cause

`Manager.Crypto().decrypt(data:)` has no key reuse. The `decrypt(using:)` overloads exist (`Data.decrypt(using:)`, `String.decrypt(using:)`) but the UI calls none of them: 68 `.decrypt()` calls under `Occulta/UI`, none batched. `ContactsV2.body` re-evaluates on every push and pop (`path` is `@State`), every search keystroke, every `@Query` change including `drafts` (so a draft save while typing in compose redraws the list underneath), and every `@AppStorage` change.

## Not the fix

A process-level cache of the local DB key. The sibling doc rejected it: the key rotates during Secure Mode activation (staged-key commit), so a cache has an invalidation risk, and it keeps the key in memory longer.

## Fix

The key is derived once per `body` pass and every field the pass opens uses it (`decrypt(using:)`), the same convention as `Group.FormV3.computeEligibility` and the vault fixes. Not a cache: nothing outlives the pass, and the key is never stored in a child view's property (that would keep it for the view's lifetime), so the children that need it derive their own once per body.

- `ContactListFilter.listing(_:atDepth:matching:usingKey:)`: visibility, names, search and sort for the list in one pass; the list body, `isEmptyList` and the footer count read it, and `statusAndCard(using:ourHash:)` and `allRecipientIdentifiers(from:usingKey:)` take the same key. No key gives an empty listing.
- `ContactDetailV2`: `headerText(key:)`, `shown(key:)` (status and card), `composeBlock(key:firstName:shown:)`; `ContactInfoSectionV2` builds `phones` and `emails` once per body; `ComposeHeroV2` takes `firstName` from the screen.
- Keyed readers beside the per-call ones, each pair sharing one private core: `hasInPersonKeys(using:ourHash:)`, `statusAndCard(using:ourHash:)`, `pairingCapabilities(using:)`, `encryptionSchemeLabel(using:)`.
- Tests: `ContactListFilterListingTests`, `ContactStatusUnderKeyTests`, `PairingCapabilitiesUnderKeyTests`: the keyed form equals the per-call form.

## Result on the iPhone 15 Pro

Same Release build, same phone, same 2-minute session each time, driven by hand.

| | Before | List | List + detail | + status read |
|---|---|---|---|---|
| Main-thread hangs (250 ms and up) | 23 | 8 | 9 | 0 |
| Total hang time | 23.6 s | 5.2 s | 3.6 s | 0 |
| Longest hang | 2.08 s | 0.89 s | 0.67 s | none |
| Hang time inside key derivation | 20.7 s | 3.2 s | 1.8 s | none |

A single derivation costs about 23 ms on this phone (single-derivation clusters in the last trace read 23–24 ms), so the 20.7 s before is about 900 derivations in the session.

## Still open

- The edit form (`Contact.FormV2`, `convertToMutableCopy`) and `GroupDetailV3` decrypt per field. They were 0.57 s and 0.22 s of hangs in the third run, and were not opened in the fourth, so they are unchanged and unmeasured since.
- The list rows (`ContactRowV2`) still decrypt their own name, thumbnail and pairing per render.
- Each keystroke in compose still derives the key once or twice in the detail body (about 23 ms each), below the hang threshold. Not measured as typing latency.
- The 68 `.decrypt()` calls elsewhere under `Occulta/UI` are unaudited.

## Not covered

One session per build, one phone, one contact count (not recorded). The fourth run did not open the edit form or a group, which the third did. The mapping from hangs to actions (navigation, search, compose) is inferred from timing, not from signposts.

# A contact whose key was revoked stays in every group with no sign of it, and the next group send fails with an opaque error

**Status: fixed in code 2026-11-14, awaiting a device check.** (Confirmed first by test, then fixed; the paragraph below describes the bug as found.) `OccultaTests/Groups/RevokedGroupMemberTests.swift` (5 tests, simulator, software keys) shows the revoked member stays in `members(atDepth: 0)`, the group send throws `contactHasNoKeys`, the shown error text is the raw enum description naming no one, and a fresh key exchange with the revoked contact makes the group send again with no re-adding. Not seen on a device, so the compose screen's exact wording is inferred from `localizedDescription`.

## Symptom

1. Revoke a contact's key (Trust Check → "phone was lost or stolen", or Edit → Revoke Key). The contact stays a member of every group it was in. Neither the revoke dialog, `GroupDetailV3` nor the group member list says anything about it.
2. Compose a message to one of those groups. By the code path below, the send throws and the user sees the raw `Error.localizedDescription` of `ContactManager.Errors.contactHasNoKeys` (that enum is not `LocalizedError`), not a sentence that names the contact or says what to do. Nothing else in the group is told why the whole message failed.

## Cause

- `ContactManager.reset(identity:)` (`Contact+Manager.swift`) stamps `expiredOn` on `contact.currentKey` and drops the inbound prekeys. It never touches `Group` membership, and the revoke call sites (`TrustCheckV2.revokeCard`, `Contact+Form`) don't look at it either. Membership is a separate store: identifiers in the group's per-depth slot arrays.
- `sendGroupBundle` resolves members from those identifiers and filters them only by `deletionToken == nil` and `isVisible(atDepth:)`. A revoked contact passes both.
- Pass 1 then calls `resolveKeyMaterial(for:)`, which reads `contact.currentKey`. A revoked contact has none (`currentKey` is the latest row with `expiredOn == nil`), so it throws `Errors.contactHasNoKeys`, and because it runs inside `members.map` the whole send aborts. No bundle is produced for anyone.
- `Group+FormV3` decides who can be added from `bundleVersionState`, which says nothing about whether a key is current. So a revoked contact is also still offered in the picker, and can be added to a group after the revoke.

## Fixed (2026-11-14)

1. **Revoke screen.** The confirmation dialog is replaced by `RevokeKeyV2` (`UI/Tabs/Contacts/v2/RevokeKeyV2.swift`), pushed from Trust Check and from the contact form. It says what a revoke does and lists the groups the contact is in at the current depth, from `ContactManager.groupNames(containing:atDepth:)` (one key derivation; one depth; nothing stored). A failed lookup or revoke says so instead of showing nothing or closing as if it worked.
2. **Group screen.** `GroupDetailV3` shows an always-visible amber notice (`GroupRevokedNoticeV3`, built on `CardNotice`) naming the members at this depth with no current key, a "KEY REVOKED" chip on their rows (in place of the green fingerprint line), and the real count: "→ 4 OF 5 RECIPIENTS", "Encrypt for 4". With every member revoked the compose box is hidden and the notice says so. The thread-style compose screen shows the same notice.
3. **Send.** `encryptGroupBundle(..., skipping:)` stops with `Errors.groupMembersWithoutKeys([identifier])` for any member without a current key that the caller didn't list. `skipping` excuses only members without keys, so it can never drop someone who can receive. `ComposeViewModel` passes the identifiers its screen displayed; a key revoked after the screen was built hits the typed error and shows "A member's key was revoked after this screen opened. Go back and open the group again." Nothing is sent. The share extension's group send keeps failing closed and now says "A member of this group has a revoked key. Open the group in Occulta to send without them."

`ContactManager.Errors` is now `Equatable` explicitly (a case with an associated value ends the implicit conformance every `#expect(throws:)` relies on).

Tests (`RevokedGroupMemberTests`, simulator, software keys): the typed error names exactly the revoked member; an excused member isn't named and an unexcused one is; skipping sends to the other two (recipient count read from the bundle); a skip entry never drops a member with a key; skipping with nobody revoked changes nothing; everyone skipped gives `groupHasNoMembers`; a fresh exchange makes the group send again with no re-adding; `groupNames` (membership, sort, per depth, none, after a revoke); the notice's wording for one, two, three, four and all. The neighbouring group, streamed-send, pairing and shard-gating suites still pass (49 tests in the run).

**Not verified:** none of the three screens has been looked at on a device (the simulator can't unlock the vault). The notice reads `givenName`/`familyName` for each revoked member on each pass, uncached, so it is cheap only while few members are revoked.

## Design reasoning (as recommended before building)

The principle: **a revoked key is a temporary state, and a send must never silently leave someone out.** So membership stays, and the app says so at the three moments the user can act on it.

1. **At revoke time, name the groups.** The confirmation dialog already says a new key exchange is needed. Add "X is in N groups (Family, Work). They won't receive group messages until you exchange keys again." Only groups with the contact at the current depth are counted.
2. **In the group, mark the member.** In `GroupDetailV3` the member row gets a "Key revoked" badge and the header a one-line note ("1 member can't receive messages"). Same in the group form's member list.
3. **At send time, before encrypting, not after failing.** Built as an always-visible notice plus a button that says who it is for ("Encrypt for 4") rather than a prompt at send: the exclusion is on screen before the user presses anything, and the typed error is the backstop if it changes in between. If every member is revoked, the compose box is hidden.

The send-side piece in `ContactManager`: `encryptGroupBundle` takes the identifiers to skip (callers pass them after the user chooses), and throws a typed `Errors.groupMembersWithoutKeys([String])` carrying identifiers, not names, when called without them. The view resolves names. Managers take identifiers, so the view passes `[String]`, never `Contact.Profile`.

### Why not remove the member on revoke

- **Re-exchange restores everything.** A revoke ends in a new key exchange. Membership is by identifier, so the group works again with no action. Auto-removal would make the user re-add the contact to every group, and nothing would tell them to.
- **It is silent too.** Removing without a notice is the same missing warning, one step further on.
- **Depths.** Membership is stored per duress depth and each depth's set is built on purpose (Bug 73). Revoke happens at one depth; removing the contact only there leaves them in the other depths' sets, and removing everywhere destroys decoy sets, which `purgeMembersFromDuressDepths` was written to avoid.

### Why not skip the member silently

The sender believes the whole group received it. A revoked contact is exactly the person the sender least wants to be left out unknowingly or, in the stolen-phone case, to still be in the loop: the sender needs to see the exclusion happen.

## Duress and forensics check

- The warning is computed from `resolvedMembers`, the same depth-filtered list `GroupDetailV3` already shows. It names no one who isn't already visible at the current depth.
- "Key revoked" is already shown on the contact itself (`ContactDetailV2`, `IdentityChallenge+View`), at every depth the contact is visible. The badge adds no fact a coercer can't already read; it doesn't contradict anything on screen, the property that made the "needs to update" label in `Group+FormV3` safe.
- No new stored field: the badge derives from `currentKey == nil`. No new write at revoke time, so no new forensic diff.
- Keep it that way: don't store "removed because revoked" in the group, and don't count revoked members across depths.

## Not covered

- A member with no current key for any other reason (a contact imported without a key) takes the same path and gets the same fix, but is not what was reported.
- Whether to also warn in `Group+FormV3` when adding an already-revoked contact: the picker should show them as unavailable ("Key revoked — exchange keys first"), probably as a fourth list beside `blocked`. Decide when this is built.

## Verification (when fixed)

1. `RevokedGroupMemberTests` already pins today's behaviour (done; all pass). With the fix, `revokedMemberFailsTheSend` and `errorIsOpaque` change: the send throws `groupMembersWithoutKeys` with exactly the revoked identifier. `baseline` and `reexchangeRestoresTheSend` stay as they are.
2. With the skip list given, a bundle is produced and the two remaining members open it; the revoked one finds no slot.
3. Re-exchange keys with the revoked contact: the group sends to all three again with no re-adding.
4. At a duress depth where the contact is hidden, the group shows no badge, no count and no banner for them.
5. Device check of the three screens (revoke dialog, group detail, compose banner).

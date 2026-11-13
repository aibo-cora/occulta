# Trust Check — top-level flow

A "Something happened?" button in the Contacts tab opens Trust Check without the user first knowing which contact to
open. The user picks what happened, picks the contact only when the scenario is about one, and reads a remedy written
for that scenario and that contact's verification state. No model, no free text. Spec: the design doc "Occulta Trust
Check — Top-Level Flow" and its mockup "Trust Check Top-Level Mockup"; this page records what was built.

## Where it lives

| File | What it holds |
|---|---|
| `Occulta/UI/Tabs/Contacts/v2/TrustCheckPlaybook.swift` | `TrustScenario`, `TrustRemedy` (a pure function of scenario, verification status and whether the key can be revoked), all remedy copy, `RevokeConfirmationCopy`, `FileNotOpenedCopy` |
| `Occulta/UI/Tabs/Contacts/v2/TrustCheckPicker.swift` | `TrustCheckPicker.rows` (testable) and the picker view |
| `Occulta/UI/Tabs/Contacts/v2/TrustCheckV2.swift` | The sheet, the remedy screen with Revoke, the contact-detail card, eligibility checks |
| `ContactsListV2.swift` | The toolbar button |
| `OccultaTests/TrustCheck/` | `TrustRemedyTests`, `TrustScenarioCopyTests`, `TrustCheckPickerDepthTests`, `TrustFileRemedyCopyTests` |

## Shape

- One sheet, `TrustCheckSheetV2(profile:)`. From the Contacts tab `profile` is nil: scenario list, then the picker for
  the four scenarios about a contact, then the remedy. From contact detail it has the contact, lists the four contact
  scenarios by name (Not verified only for a Not verified contact) and skips the picker. The Hide card shows only there.
- The picker lists every visible contact and marks, rather than hides, the ones a scenario can't act on. Rows whose remedy
  acts (Challenge, Revoke) sort first, then a divider, then the rest. "A contact shows Not verified" is the one scenario
  that narrows its list, to Not verified contacts. Rows come from `ContactListFilter` and nothing else.
- Revoke is reachable from here: the remedy screen shows the contact's avatar and name, the button names them, and so
  does the confirmation. It calls `ContactManager.reset(identity:)` with the identifier.
- The scenario and contact live in the navigation stack only. Never persisted, logged or donated.

## Depth

Entry point, scenarios and remedies are identical at every depth; only the picker's rows differ. The checklist and how
each item is enforced is `Occulta/Features/SecureMode/forensic-trace-avoidance.md` U7.

## Differences from the design and mockup

- The remedy for "someone sent a suspicious call or message" and "new phone" for Not verified and Pending contacts, and
  the Not verified remedy, use the design's table text lightly reworded into sentences; only the key-change copy is
  the approved wording verbatim.
- The mockup darkened the accent, danger and warn colours where small text sits on or under them (4.5:1). The app's
  tokens are unchanged; the picker's chip and remedy line use `occultaDanger`, `occultaWarn` and `occultaVerified` as
  they are. **Open, needs a decision:** whether to darken those tokens, or add text variants.
- The signed-text scenario explains and does not open the Verify tab: there is no tab switch to hook into from a sheet,
  and the scenario is off while `FeatureFlags.signature` is.
- "A file won't open" has no per-contact state, so it never reaches the picker.

## Known issues on this path

Bug 194 (fixed in #156) and the copy question in Bug 82 (`bugs.md`) were the two blockers; Bug 82a, whether superseded
keys are accepted, is still open there, which is why the copy promises nothing for a plain re-exchange.

# "Erase All Data" is a single unconfirmed tap, reachable by whoever is holding the phone

**Status:** open, unscoped — no fix proposed yet. Found while reviewing the Settings redesign shipped this release (`442b0c4`), which moved this action into its own labeled "Data" section, making it more prominent than before, not less.

## Symptom

Settings → Data → **Erase All Data** (`Settings.swift`, `ManageContacts` view) is one tap away from permanently destroying the entire app: every contact, the entire vault, all prekeys, and every Secure Enclave key. There is no confirmation dialog, no re-authentication, and no depth-awareness.

```swift
// Settings.swift:155-170
private struct ManageContacts: View {
    @Environment(Manager.App.self) private var appManager: Manager.App

    var body: some View {
        VStack(spacing: 20) {
            Text("Delete **entire** contact database, vault, private keys and stored messages.")
            Text("This cannot be undone.").italic()

            Button("Delete", role: .destructive) {
                try? self.appManager.eraseAllData()
            }
            .prominentButtonStyle()
        }
        .padding()
    }
}
```

`role: .destructive` only styles the button red — it does not add a system confirmation. No `.alert` or `.confirmationDialog` wraps this call anywhere in the file. Tapping "Erase All Data" then "Delete" is two taps, zero friction, from an empty app.

## What actually happens

`Manager.App.eraseAllData()` (`Manager+App.swift:22`):

```swift
func eraseAllData() throws {
    Manager.PrekeyManager().deleteAllKeys()
    try self.contacts.deleteAllContacts()
    try self.vault.deleteAllData()
    Manager.Key().deleteAllKeys()
}
```

- `ContactManager.deleteAllContacts()` — hard-deletes every `Contact.Profile` row, including soft-deleted ones. Its own doc comment: *"Used for panic wipe only."*
- `VaultManager.deleteAllData()` — deletes every vault entry plus `BackupEncryptionKey`, `CustodyShard`, `PendingShardDistribute`, `GlobalShardConfig`, and **`AppLayerConfig`** — the table holding the sealed normal *and* duress PIN verifiers. Wiping it doesn't just clear the vault, it removes Secure Mode's own configuration.
- `Manager.Key().deleteAllKeys()` — deletes every Secure Enclave key by tag, plus the local-DB Keychain component. Its own doc comment: *"After this call every encrypted blob in Occulta is permanently unreadable."*

None of this is depth-scoped. There is no concept of "wipe just the duress layer" — it is unconditionally everything, at every depth, real and hidden alike.

## Why this matters given the threat model

This codebase's whole premise is surviving a coercer's inspection without a tell. Two ways this specific screen works against that:

1. **No friction between curiosity and total loss.** A coercer forcing the victim to unlock and explore the phone — or the victim themselves, panicking under pressure — can trigger irreversible, total destruction with two taps and no "are you sure." Compare this to `SecuritySettings`' own "Deactivate Protection" button (`Settings.swift:235-239`), the only other genuinely destructive action in Settings: that one requires routing through `SecureModeDeactivateFlow`, a full PIN-verification sheet, before anything happens. Erase-all-data has no equivalent gate.
2. **An emptied app is itself a tell.** Per this codebase's forensic-trace-clean standard, a device that goes from "populated contact book and vault" to "completely empty" the instant someone pokes at Settings reads as *proof* something was being hidden — plausibly a worse outcome under coercion than whatever the data itself would have revealed.

Item 1 also cuts the other way: `deleteAllContacts` is explicitly commented as "panic wipe" — i.e. this *is* meant to exist as a deliberate self-destruct for the victim. The bug isn't that the capability exists; it's that it's undifferentiated from an accidental or coercer-triggered tap, sitting in plain Settings with no distinguishing ceremony.

## This session's redesign made it more visible, not less

Before `442b0c4`, this was a plain `NavigationLink("Manage Contacts")` row in a flat six-row list. The Settings redesign gave it its own section, header ("Permanently erase all local data. This cannot be undone."), and relabeled the link itself "Erase All Data" in red. That was a deliberate design choice to make a destructive action legible — but it also means anyone scanning Settings now sees it immediately, without having to open "Manage Contacts" first to discover what it does. Worth weighing when scoping a fix: more visible is correct for an intentional user action, wrong for a coercer's idle exploration.

## Not yet decided

- Add a confirmation step (`.confirmationDialog` at minimum, PIN re-entry to match `SecuritySettings`' bar for the other destructive action) — cheapest fix, doesn't touch the underlying capability.
- Whether visibility/reachability of this row should itself depend on `Manager.Security` state (e.g. hidden or relabeled under an active duress state) — bigger, and risks becoming its own tell if the Settings list visibly changes shape under duress.
- Whether "panic wipe" as a *deliberate* victim action deserves a distinct, harder-to-stumble-into entry point, separate from routine data management — the current single button conflates "I did this on purpose" with "someone else's finger landed here."

No implementation attempted. Scoping only.

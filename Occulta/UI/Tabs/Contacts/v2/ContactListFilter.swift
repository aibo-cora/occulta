//
//  ContactListFilter.swift
//  Occulta
//
//  Depth filtering, search, and sort order for every list of contacts or groups the user
//  picks from. Shared by `ContactsV2` and `ShareRecipientPicker` so the two screens cannot
//  drift — a contact hidden in one and shown in the other is the Bug 25 / Bug 28 failure.
//
//  Lifted out of `ContactsV2`'s computed properties so it can be tested without a `View`.
//

import Foundation

enum ContactListFilter {

    /// Contacts visible at `depth`. Everything classified deeper is absent from this list,
    /// which is what keeps sensitive contacts out of a duress-depth view.
    static func visibleContacts(_ contacts: [Contact.Profile], atDepth depth: Int) -> [Contact.Profile] {
        contacts.filter { $0.isVisible(atDepth: depth) }
    }

    /// Search-filtered and sorted for display: family name first when either side has one,
    /// given name otherwise.
    static func sortedContacts(_ contacts: [Contact.Profile], matching searchText: String) -> [Contact.Profile] {
        let source = searchText.isEmpty ? contacts : contacts.filter {
            $0.givenName.decrypt().localizedStandardContains(searchText)
            || $0.familyName.decrypt().localizedStandardContains(searchText)
            || $0.organizationName.decrypt().localizedStandardContains(searchText)
        }

        return source.sorted {
            let lf = $0.familyName.decrypt(), rf = $1.familyName.decrypt()

            if !lf.isEmpty || !rf.isEmpty { return lf < rf }

            return $0.givenName.decrypt() < $1.givenName.decrypt()
        }
    }

    static func sortedGroups(_ groups: [Group], matching searchText: String) -> [Group] {
        let source = searchText.isEmpty ? groups : groups.filter {
            ($0.readName() ?? "").localizedStandardContains(searchText)
        }
        return source.sorted { ($0.readName() ?? "") < ($1.readName() ?? "") }
    }

    /// Groups that can actually receive a message at `depth`.
    ///
    /// Membership is per-depth (Bug 73), so a group can be visible and still have nobody in
    /// it at the current depth. `encryptGroupBundle` throws `groupHasNoMembers` for those —
    /// filtering here means the picker never offers a recipient that cannot be encrypted for.
    static func groupsWithMembers(_ groups: [Group], atDepth depth: Int) -> [Group] {
        groups.filter { !$0.members(atDepth: depth).isEmpty }
    }
}

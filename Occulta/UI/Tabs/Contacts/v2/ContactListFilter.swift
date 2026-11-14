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
import CryptoKit

enum ContactListFilter {

    /// A contact with the names the list sorts and searches by, opened once.
    struct Entry {
        let contact: Contact.Profile
        let givenName: String
        let familyName: String
    }

    /// What the contacts list draws. `visible` is everyone at the depth, whatever the search says: the empty
    /// state and the count are decided on it. `shown` is `visible` after search and sort.
    struct Listing {
        let visible: [Entry]
        let shown: [Entry]

        static let empty = Listing(visible: [], shown: [])
    }

    /// `visibleContacts`, `isEmptyList` and `sortedContacts` for one pass of the list, under a key the caller
    /// derived once. Those three open the same fields again on every call, and each open derives the key afresh
    /// (the Enclave-bound derivation: hangs of 0.7 to 2 s a pass on an iPhone 15 Pro, `Docs/Bugs/v2.1.0/`), so the
    /// list's body paid for them several times over, and the sort paid for them on every comparison.
    ///
    /// No key gives an empty listing, as `Group.FormV3.computeEligibility` does: without one `isVisible` treats
    /// every classified contact as hidden, and every contact is classified once it has been created.
    static func listing(
        _ contacts: [Contact.Profile],
        atDepth depth: Int,
        matching searchText: String,
        usingKey key: SymmetricKey?
    ) -> Listing {
        guard let key else { return .empty }

        let visible = contacts
            .filter { $0.isVisible(atDepth: depth, usingKey: key) }
            .map { Entry(contact: $0, givenName: $0.givenName.decrypt(using: key), familyName: $0.familyName.decrypt(using: key)) }

        let matching = searchText.isEmpty ? visible : visible.filter {
            $0.givenName.localizedStandardContains(searchText)
            || $0.familyName.localizedStandardContains(searchText)
            || $0.contact.organizationName.decrypt(using: key).localizedStandardContains(searchText)
        }

        let shown = matching.sorted {
            if !$0.familyName.isEmpty || !$1.familyName.isEmpty { return $0.familyName < $1.familyName }

            return $0.givenName < $1.givenName
        }

        return Listing(visible: visible, shown: shown)
    }

    /// Contacts visible at `depth`. Everything classified deeper is absent from this list,
    /// which is what keeps sensitive contacts out of a duress-depth view.
    static func visibleContacts(_ contacts: [Contact.Profile], atDepth depth: Int) -> [Contact.Profile] {
        contacts.filter { $0.isVisible(atDepth: depth) }
    }

    /// Whether the contacts screen is in its empty state at `depth`: no trust summary, the create-contact hint.
    /// Decided on what is visible, not on what is stored. Reading the unfiltered list tells a duress-depth
    /// viewer whether hidden contacts exist, since a genuinely empty install shows the hint and this would not.
    static func isEmptyList(_ contacts: [Contact.Profile], atDepth depth: Int) -> Bool {
        self.visibleContacts(contacts, atDepth: depth).isEmpty
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

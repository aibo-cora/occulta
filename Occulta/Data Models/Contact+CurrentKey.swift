//
//  Contact+CurrentKey.swift
//  Occulta
//
//  Which of a contact's key rows every send and receive uses (`bugs.md` Bug 196).
//

import Foundation

extension Contact.Profile {

    /// The key row every send and receive uses: the latest one not expired. A re-pair expires the rows before it in the
    /// save that adds the new one (`ContactManager.update(key:for:pairing:)`), so at most one row is ever current. A
    /// to-many relationship has no order of its own, so `.last` of the whole list can be a retired row.
    var currentKey: Key? {
        self.contactPublicKeys?.last(where: { $0.expiredOn == nil })
    }

    /// The key row to show: the current one, else whichever row is latest, for a contact whose key was revoked.
    var displayedKey: Key? {
        self.currentKey ?? self.contactPublicKeys?.last
    }
}

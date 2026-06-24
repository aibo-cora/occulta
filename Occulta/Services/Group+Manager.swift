//
//  Group+Manager.swift
//  Occulta
//

import Foundation
import SwiftData

enum IneligibilityReason {
    /// `maxBundleVersion == nil` — contact has never sent a bundle; version is unproven.
    /// UI copy: "Ask them to send you a message"
    case versionUnknown
    /// Version is known but below 1.9.0.
    /// UI copy: "Ask them to update Occulta"
    case versionTooOld
}

final class GroupManager {

    // MARK: - Version gating

    /// True when the contact's app can process group bundles (≥ 1.9.0).
    func isEligible(_ contact: Contact.Profile, crypto: Manager.Crypto = Manager.Crypto()) -> Bool {
        ContactManager.resolveTargetVersion(for: contact, using: crypto).supportsGroups
    }

    /// Why a contact cannot be added to a group. Nil when the contact is eligible.
    func ineligibilityReason(
        for contact: Contact.Profile,
        crypto: Manager.Crypto = Manager.Crypto()
    ) -> IneligibilityReason? {
        guard !self.isEligible(contact, crypto: crypto) else { return nil }
        return contact.maxBundleVersion == nil ? .versionUnknown : .versionTooOld
    }

    // MARK: - CRUD

    func create(name: String, in context: ModelContext) throws -> Group {
        let group = try Group(name: name)
        context.insert(group)
        return group
    }

    func delete(_ group: Group, from context: ModelContext) {
        context.delete(group)
    }

    func allGroups(in context: ModelContext) throws -> [Group] {
        try context.fetch(FetchDescriptor<Group>())
    }

    // MARK: - Members

    /// Resolves the active layer's contact identifiers to Contact.Profile objects.
    /// Profiles that have been hard-deleted since the member was added return no entry.
    func resolveMembers(
        of group: Group,
        in layer: RoutingDepth,
        context: ModelContext
    ) throws -> [Contact.Profile] {
        let identifiers = Set(group.members(in: layer))
        guard !identifiers.isEmpty else { return [] }
        let all = try context.fetch(FetchDescriptor<Contact.Profile>())
        return all.filter { identifiers.contains($0.identifier) }
    }
}

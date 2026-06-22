//
//  Group+Manager.swift
//  Occulta
//

import Foundation
import SwiftData

final class GroupManager {

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

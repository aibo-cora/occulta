//
//  Contact+Manager+Groups.swift
//  Occulta
//

import SwiftData
import Foundation

// MARK: - IneligibilityReason

enum IneligibilityReason {
    /// Contact has never sent a bundle; version is unproven.
    case versionUnknown
    /// Version is known but below 1.9.0.
    case versionTooOld
}

// MARK: - Group operations

extension ContactManager {

    // MARK: CRUD
    @discardableResult
    func createGroup(name: String) throws -> Group {
        let group = try Group(name: name)
        
        self.modelContext.insert(group)
        try self.modelContext.save()
        
        return group
    }

    /// Deletes the group with the given ID. No-ops silently if the ID is not found.
    func deleteGroup(id: UUID) throws {
        guard let group = try self.group(withID: id) else { return }
        
        self.modelContext.delete(group)
        try self.modelContext.save()
    }

    /// Fetches every group from the store.
    /// Views should use `@Query` instead. This is intended for test use only — CRUD
    /// tests require the Secure Enclave (group name/ID are encrypted) and will skip
    /// on simulator via `secureEnclaveAvailable()`.
    func allGroups() throws -> [Group] {
        try self.modelContext.fetch(FetchDescriptor<Group>())
    }

    // MARK: Members

    func addGroupMember(_ memberIdentifier: String, toGroupID groupID: UUID, in layer: RoutingDepth) throws {
        guard let group = try self.group(withID: groupID) else { throw Errors.groupIDMissing }
        
        try group.addMember(memberIdentifier, in: layer)
        try self.modelContext.save()
    }

    func removeGroupMember(_ memberIdentifier: String, fromGroupID groupID: UUID, in layer: RoutingDepth) throws {
        guard let group = try self.group(withID: groupID) else { throw Errors.groupIDMissing }
        
        try group.removeMember(memberIdentifier, in: layer)
        
        try self.modelContext.save()
    }

    // MARK: Eligibility

    /// Returns true if the contact with the given identifier can receive group bundles.
    /// Returns false if the contact is not found.
    func isGroupEligible(identifier: String, crypto: Manager.Crypto = Manager.Crypto()) throws -> Bool {
        guard let contact = try self.fetchContact(by: identifier) else { return false }
        
        return Self.resolveTargetVersion(for: contact, using: crypto).supportsGroups
    }

    /// Returns why a contact cannot be added to a group, or nil if eligible.
    /// Returns nil if the contact is not found.
    func groupIneligibilityReason(for identifier: String, crypto: Manager.Crypto = Manager.Crypto()) throws -> IneligibilityReason? {
        guard let contact = try self.fetchContact(by: identifier) else { return nil }
        guard !Self.resolveTargetVersion(for: contact, using: crypto).supportsGroups else { return nil }
        
        return contact.maxBundleVersion == nil ? .versionUnknown : .versionTooOld
    }

    // MARK: Test support

    /// Inserts a raw profile directly into the store. Use in tests only.
    func insertProfile(_ profile: Contact.Profile) throws {
        self.modelContext.insert(profile)
        try self.modelContext.save()
    }

    // MARK: Private

    private func group(withID id: UUID) throws -> Group? {
        try self.modelContext.fetch(FetchDescriptor<Group>()).first { $0.readID() == id }
    }
}

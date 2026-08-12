//
//  Contact+Manager+Groups.swift
//  Occulta
//

import CryptoKit
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

    func addGroupMember(_ memberIdentifier: String, toGroupID groupID: UUID, atDepth depth: Int) throws {
        guard let group = try self.group(withID: groupID) else { throw Errors.groupIDMissing }

        try group.addMember(memberIdentifier, atDepth: depth)
        try self.modelContext.save()
    }

    func removeGroupMember(_ memberIdentifier: String, fromGroupID groupID: UUID, atDepth depth: Int) throws {
        guard let group = try self.group(withID: groupID) else { throw Errors.groupIDMissing }

        try group.removeMember(memberIdentifier, atDepth: depth)

        try self.modelContext.save()
    }

    // MARK: Orphan repair

    /// Deletes `Group` rows whose identifier no longer decrypts under the canonical local DB
    /// key — rows stranded by a Secure Mode key rotation that predates `Group.reencrypt`
    /// (Bug 75). Silent by design: the user already perceives these groups as missing, and
    /// any explanation would have to gesture at Secure Mode.
    ///
    /// **Why deleting is safe.** The stranded ciphertext is not merely unreadable now, it is
    /// unreadable forever. The hybrid key needs both an SE private key and a Keychain random
    /// component; activation's Step 11 destroys both, and the SE half is non-exportable by
    /// construction — no backup, on this device or any other, can bring it back. So no repair
    /// path can ever exist, and these rows are provably dead: unopenable, unmessageable, and
    /// undeletable through the UI, since every path there resolves a group via `readID()`.
    /// Removing them also closes a forensic tell — undecryptable rows sitting beside
    /// decryptable ones are visible evidence that a key rotation happened.
    ///
    /// **`key` is a parameter, not derived here, and that is deliberate.** If derivation
    /// failed and this treated a nil key as "inspect anyway", every group would look stranded
    /// and the whole table would be deleted. Requiring the key makes that state
    /// unrepresentable rather than merely guarded: there is no way to run this without one.
    /// The caller is responsible for supplying a genuinely derived canonical key — pass
    /// anything else and every row will be judged stranded, which is the honest consequence
    /// of the key being wrong. Once a real key is in hand, AES-GCM does not fail transiently,
    /// so a decryption failure under it means the row genuinely is stranded.
    ///
    /// Costs one decrypt per group, not one per slot: nothing here touches member slots, so
    /// Bug 74's Secure Enclave round-trip ceiling is nowhere near.
    ///
    /// Callers must gate on depth 0. See the call site in `OccultaApp`.
    func purgeUnreadableGroups(using key: SymmetricKey) throws {
        var removed = false
        for group in try self.modelContext.fetch(FetchDescriptor<Group>())
        where group.encryptedID?.decrypt(using: key) == nil {
            self.modelContext.delete(group)
            removed = true
        }
        if removed {
            try self.modelContext.save()
        }

        // Unconditional, exactly as `checkpointStore()` documents: a checkpoint that fired
        // only when something was deleted would make checkpoint timing itself the signal for
        // "this device had stranded groups."
        self.security.checkpointStore()
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

    func group(withID id: UUID) throws -> Group? {
        try self.modelContext.fetch(FetchDescriptor<Group>()).first { $0.readID() == id }
    }

    /// Applies `operation` to every stored group, then saves once. Used by classification
    /// and deletion cleanup, which must touch every group uniformly — see
    /// `Group.purgeMembersFromDuressDepths(_:)`, `Group.refreshCiphertext()`, and `Group.purgeMember(_:)`.
    func forEachGroup(_ operation: (Group) throws -> Void) throws {
        for group in try self.modelContext.fetch(FetchDescriptor<Group>()) {
            try operation(group)
        }
        try self.modelContext.save()
    }
}

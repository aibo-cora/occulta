//
//  GroupModelTests.swift
//  OccultaTests
//
//  Structural tests (slot counts, sizes, random filler) are simulator safe —
//  they test Group.freshFillerArray() and static constants directly, no SE needed.
//
//  Encrypted round-trip tests (add/remove member, name, ID, createdAt) require
//  the Secure Enclave and guard on secureEnclaveAvailable().
//

import Testing
import Foundation
import SwiftData
@testable import Occulta

// MARK: - Helpers

private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

@MainActor
private func makeContainer() throws -> ModelContainer {
    let schema = Schema([
        Group.self,
        Contact.Profile.self,
        Contact.Profile.PhoneNumber.self,
        Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self,
        Contact.Profile.URLAddress.self,
        Contact.Profile.Key.self,
    ])
    return try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
}

// MARK: - Structural invariants (simulator safe)

@Suite("Group — structural invariants")
struct GroupStructuralTests {

    @Test func constants_slotCount_is32() {
        #expect(Group.slotCount == 32)
    }

    @Test func constants_slotSize_is156() {
        #expect(Group.slotSize == 156)
    }

    @Test func freshFillerArray_count_is32() throws {
        #expect(try Group.freshFillerArray().count == Group.slotCount)
    }

    @Test func freshFillerArray_allSlots_are156bytes() throws {
        for slot in try Group.freshFillerArray() {
            #expect(slot.count == Group.slotSize)
        }
    }

    @Test func freshFillerArray_isRandom_twoCallsDiffer() throws {
        let a = try Group.freshFillerArray()
        let b = try Group.freshFillerArray()
        #expect(a != b, "Two fresh filler arrays must differ — each slot is cryptographically random")
    }

    @Test func twoFreshFillerArrays_areIndependent() throws {
        // Real and duress arrays initialised from independent freshFillerArray() calls must differ.
        let real   = try Group.freshFillerArray()
        let duress = try Group.freshFillerArray()
        #expect(real != duress)
    }
}

// MARK: - Encrypted round-trips (require SE)

@Suite("Group — encrypted round-trips")
@MainActor struct GroupEncryptedTests {

    @Test func addMember_readsBackAtSameDepth() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx = ModelContext(try makeContainer())
        let group = try Group(name: "Friends")
        ctx.insert(group)

        let id = UUID().uuidString
        try group.addMember(id, atDepth: 0)
        #expect(group.members(atDepth: 0).contains(id))
    }

    @Test func addMember_doesNotAppearInOtherLayer() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx = ModelContext(try makeContainer())
        let group = try Group(name: "Friends")
        ctx.insert(group)

        try group.addMember(UUID().uuidString, atDepth: 0)
        #expect(group.members(atDepth: 1).isEmpty, "Real member must not leak into duress layer")
    }

    @Test func addMember_allSlotsRemain156bytes() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx = ModelContext(try makeContainer())
        let group = try Group(name: "Family")
        ctx.insert(group)

        try group.addMember(UUID().uuidString, atDepth: 0)

        #expect(group.realMemberSlots.count == Group.slotCount)
        for slot in group.realMemberSlots {
            #expect(slot.count == Group.slotSize)
        }
    }

    @Test func addMember_longIdentifier_readsBack() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx = ModelContext(try makeContainer())
        let group = try Group(name: "Test")
        ctx.insert(group)

        // CNContact identifiers can exceed 36 chars (observed 88 bytes on device).
        // This test guards against the previous str.count == 36 regression.
        let longID = UUID().uuidString + ":ABPerson:extra-suffix-padding-bytes-here"
        try group.addMember(longID, atDepth: 0)
        #expect(group.members(atDepth: 0) == [longID])
        for slot in group.realMemberSlots {
            #expect(slot.count == Group.slotSize, "All slots must be identical size after add")
        }
    }

    @Test func addMember_fullRecompute_everyDepthChanges() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx = ModelContext(try makeContainer())
        let group = try Group(name: "Team")
        ctx.insert(group)

        let beforeReal   = group.realMemberSlots
        let beforeDuress = group.duressMemberSlots
        let beforeDeeper = group.deeperMemberSlots
        try group.addMember(UUID().uuidString, atDepth: 0)
        // Every depth must change — if only the target depth changed, a DB diff would
        // reveal which depth was written (Bug 73).
        #expect(beforeReal   != group.realMemberSlots)
        #expect(beforeDuress != group.duressMemberSlots)
        #expect(beforeDeeper != group.deeperMemberSlots)
    }

    @Test func deeperDuressDepths_areIndependentFromEachOtherAndFromDepth1() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx = ModelContext(try makeContainer())
        let group = try Group(name: "MultiLayer")
        ctx.insert(group)

        // Regression test for Bug 73: before the fix, every depth > 0 shared one
        // `duressMemberSlots` array, so a "different decoy per layer" setup (the
        // documented multi-layer feature) silently collapsed into a single list.
        let depth1ID = UUID().uuidString
        let depth2ID = UUID().uuidString
        let depth3ID = UUID().uuidString
        try group.addMember(depth1ID, atDepth: 1)
        try group.addMember(depth2ID, atDepth: 2)
        try group.addMember(depth3ID, atDepth: 3)

        #expect(group.members(atDepth: 1) == [depth1ID])
        #expect(group.members(atDepth: 2) == [depth2ID])
        #expect(group.members(atDepth: 3) == [depth3ID])
    }

    @Test func editingDeepDepth_doesNotClobberShallowerDepths() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx = ModelContext(try makeContainer())
        let group = try Group(name: "Layered")
        ctx.insert(group)

        let depth1ID = UUID().uuidString
        try group.addMember(depth1ID, atDepth: 1)

        // Editing depth 2 — the exact scenario from the bug report — must not touch
        // depth 1's already-established membership.
        try group.addMember(UUID().uuidString, atDepth: 2)
        #expect(group.members(atDepth: 1) == [depth1ID])
    }

    @Test func newGroup_deeperSlots_prePaddedAndStayFullSizeAcrossEdits() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx = ModelContext(try makeContainer())
        let group = try Group(name: "Layered")
        ctx.insert(group)

        // Groups created at/after 1.9.1 are pre-padded at init (unlike pre-1.9.1 rows,
        // which start with an empty deeperMemberSlots and get padded lazily by
        // ensureDeeperSlotsPadded() on their first post-upgrade edit — not exercisable
        // from this black-box test since Group has no legacy-row constructor).
        #expect(group.deeperMemberSlots.count == Group.depthCount - 2)

        try group.addMember(UUID().uuidString, atDepth: 0)
        try group.addMember(UUID().uuidString, atDepth: 1)
        try group.addMember(UUID().uuidString, atDepth: 5)

        #expect(group.deeperMemberSlots.count == Group.depthCount - 2)
        for slots in group.deeperMemberSlots {
            #expect(slots.count == Group.slotCount)
        }
    }

    @Test func members_outOfRangeDepth_returnsEmptyWithoutCrashing() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx = ModelContext(try makeContainer())
        let group = try Group(name: "Bounds")
        ctx.insert(group)

        #expect(group.members(atDepth: -1).isEmpty)
        #expect(group.members(atDepth: Group.depthCount).isEmpty)
        #expect(group.members(atDepth: 999).isEmpty)
    }

    @Test func addMember_depthAtOrBeyondDepthCount_throwsInvalidDepth() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx = ModelContext(try makeContainer())
        let group = try Group(name: "Bounds")
        ctx.insert(group)

        #expect(throws: GroupError.invalidDepth) {
            try group.addMember(UUID().uuidString, atDepth: Group.depthCount)
        }
    }

    @Test func removeMember_noLongerReadable() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx = ModelContext(try makeContainer())
        let group = try Group(name: "Crew")
        ctx.insert(group)

        let id = UUID().uuidString
        try group.addMember(id, atDepth: 0)
        try group.removeMember(id, atDepth: 0)
        #expect(group.members(atDepth: 0).isEmpty)
    }

    @Test func addMember_duplicate_isIdempotent() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx = ModelContext(try makeContainer())
        let group = try Group(name: "Club")
        ctx.insert(group)

        let id = UUID().uuidString
        try group.addMember(id, atDepth: 0)
        try group.addMember(id, atDepth: 0)
        #expect(group.members(atDepth: 0).count == 1)
    }

    @Test func addMember_exceeds32_throwsCapacityExceeded() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx = ModelContext(try makeContainer())
        let group = try Group(name: "Large")
        ctx.insert(group)

        for _ in 0..<Group.slotCount {
            try group.addMember(UUID().uuidString, atDepth: 0)
        }
        #expect(throws: GroupError.capacityExceeded) {
            try group.addMember(UUID().uuidString, atDepth: 0)
        }
    }

    @Test func removeFirst_then_add_atCapacity_succeeds() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx = ModelContext(try makeContainer())
        let group = try Group(name: "Full")
        ctx.insert(group)

        var ids = (0..<Group.slotCount).map { _ in UUID().uuidString }
        for id in ids { try group.addMember(id, atDepth: 0) }

        // Remove one then add one — the correct order used by saveGroup after F-21 fix.
        let removed = ids.removeFirst()
        let added   = UUID().uuidString
        try group.removeMember(removed, atDepth: 0)
        try group.addMember(added, atDepth: 0)

        let members = Set(group.members(atDepth: 0))
        #expect(!members.contains(removed))
        #expect(members.contains(added))
        #expect(members.count == Group.slotCount)
    }

    @Test func addFirst_atCapacity_throwsBeforeRemove() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx = ModelContext(try makeContainer())
        let group = try Group(name: "Full")
        ctx.insert(group)

        var ids = (0..<Group.slotCount).map { _ in UUID().uuidString }
        for id in ids { try group.addMember(id, atDepth: 0) }

        // Adding before removing at capacity must throw — this is the failure mode
        // that the old saveGroup order would hit, leaving the group unchanged.
        let toRemove = ids[0]
        let toAdd    = UUID().uuidString
        #expect(throws: GroupError.capacityExceeded) {
            try group.addMember(toAdd, atDepth: 0)
        }
        // Group is unchanged after the failed add.
        #expect(group.members(atDepth: 0).contains(toRemove))
        #expect(!group.members(atDepth: 0).contains(toAdd))
    }

    @Test func duressLayer_independentFromRealLayer() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx = ModelContext(try makeContainer())
        let group = try Group(name: "Dual")
        ctx.insert(group)

        let realID   = UUID().uuidString
        let duressID = UUID().uuidString
        try group.addMember(realID,   atDepth: 0)
        try group.addMember(duressID, atDepth: 1)

        #expect(group.members(atDepth: 0) == [realID])
        #expect(group.members(atDepth: 1) == [duressID])
    }

    @Test func readName_roundTrip() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx = ModelContext(try makeContainer())
        let group = try Group(name: "Alpha Team")
        ctx.insert(group)
        #expect(group.readName() == "Alpha Team")
    }

    @Test func writeName_updatesReadName() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx = ModelContext(try makeContainer())
        let group = try Group(name: "Old")
        ctx.insert(group)
        try group.writeName("New")
        #expect(group.readName() == "New")
    }

    @Test func readID_isValidUUID() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx = ModelContext(try makeContainer())
        let group = try Group(name: "Test")
        ctx.insert(group)
        #expect(group.readID() != nil)
    }

    @Test func readCreatedAt_isSecondPrecision() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx = ModelContext(try makeContainer())
        let before = floor(Date().timeIntervalSince1970)
        let group = try Group(name: "Dated")
        ctx.insert(group)
        let after = floor(Date().timeIntervalSince1970)

        guard let ts = group.readCreatedAt()?.timeIntervalSince1970 else {
            Issue.record("readCreatedAt returned nil"); return
        }
        #expect(ts == floor(ts), "createdAt must have no fractional seconds")
        #expect(ts >= before && ts <= after)
    }
}

// MARK: - ContactManager — Group CRUD

@Suite("ContactManager — Group CRUD")
@MainActor struct GroupManagerTests {

    private func makeContactManager() throws -> ContactManager {
        let container = try makeContainer()
        let security  = try Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        return ContactManager(modelContainer: container, security: security)
    }

    @Test func create_insertsGroup() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let cm  = try self.makeContactManager()
        _       = try cm.createGroup(name: "Ops")
        let all = try cm.allGroups()
        #expect(all.count == 1)
        #expect(all[0].readName() == "Ops")
    }

    @Test func delete_removesGroup() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let cm    = try self.makeContactManager()
        let group = try cm.createGroup(name: "Temp")
        guard let id = group.readID() else { Issue.record("readID() returned nil"); return }
        try cm.deleteGroup(id: id)
        #expect(try cm.allGroups().isEmpty)
    }

}

// MARK: - ContactManager — Group eligibility
// Simulator safe — uses TestKeyManager for maxBundleVersion encryption/decryption;
// no Secure Enclave required. Contacts are inserted into an in-memory store.

@Suite("ContactManager — Group eligibility")
@MainActor struct GroupEligibilityTests {

    private func makeContactManager(crypto: Manager.Crypto) throws -> ContactManager {
        let container = try makeContainer()
        let security  = try Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        return ContactManager(modelContainer: container, security: security)
    }

    private func insertedContact(withVersionByte byte: UInt8?, crypto: Manager.Crypto, in cm: ContactManager) throws -> Contact.Profile {
        let c = Contact.Profile(
            identifier: UUID().uuidString, givenName: "Test", familyName: "U",
            middleName: "", nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        if let byte {
            c.maxBundleVersion = try crypto.encrypt(data: Data([byte]))
        }
        try cm.insertProfile(c)
        return c
    }

    @Test func eligible_groupCapableByte_returnsTrue() throws {
        let km     = TestKeyManager()
        let crypto = Manager.Crypto(keyManager: km)
        let cm     = try self.makeContactManager(crypto: crypto)
        let c      = try self.insertedContact(withVersionByte: 0x05, crypto: crypto, in: cm)
        #expect(try cm.isGroupEligible(identifier: c.identifier, crypto: crypto))
    }

    @Test func ineligible_v4Byte_returnsFalse() throws {
        let km     = TestKeyManager()
        let crypto = Manager.Crypto(keyManager: km)
        let cm     = try self.makeContactManager(crypto: crypto)
        let c      = try self.insertedContact(withVersionByte: 0x04, crypto: crypto, in: cm)
        #expect(try !cm.isGroupEligible(identifier: c.identifier, crypto: crypto))
    }

    @Test func ineligible_noVersionByte_returnsFalse() throws {
        let km     = TestKeyManager()
        let crypto = Manager.Crypto(keyManager: km)
        let cm     = try self.makeContactManager(crypto: crypto)
        let c      = try self.insertedContact(withVersionByte: nil, crypto: crypto, in: cm)
        #expect(try !cm.isGroupEligible(identifier: c.identifier, crypto: crypto))
    }

    @Test func ineligibilityReason_noVersionByte_isUnknown() throws {
        let km     = TestKeyManager()
        let crypto = Manager.Crypto(keyManager: km)
        let cm     = try self.makeContactManager(crypto: crypto)
        let c      = try self.insertedContact(withVersionByte: nil, crypto: crypto, in: cm)
        #expect(try cm.groupIneligibilityReason(for: c.identifier, crypto: crypto) == .versionUnknown)
    }

    @Test func ineligibilityReason_v4Byte_isTooOld() throws {
        let km     = TestKeyManager()
        let crypto = Manager.Crypto(keyManager: km)
        let cm     = try self.makeContactManager(crypto: crypto)
        let c      = try self.insertedContact(withVersionByte: 0x04, crypto: crypto, in: cm)
        #expect(try cm.groupIneligibilityReason(for: c.identifier, crypto: crypto) == .versionTooOld)
    }

    @Test func ineligibilityReason_eligible_isNil() throws {
        let km     = TestKeyManager()
        let crypto = Manager.Crypto(keyManager: km)
        let cm     = try self.makeContactManager(crypto: crypto)
        let c      = try self.insertedContact(withVersionByte: 0x05, crypto: crypto, in: cm)
        #expect(try cm.groupIneligibilityReason(for: c.identifier, crypto: crypto) == nil)
    }
}

// MARK: - ContactManager — encryptGroupBundle recipient filtering

@Suite("ContactManager — encryptGroupBundle recipient filtering")
@MainActor struct GroupEncryptRecipientFilteringTests {

    private func makeContactManager() throws -> ContactManager {
        let container = try makeContainer()
        let security  = try Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        return ContactManager(modelContainer: container, security: security)
    }

    /// Returns nil (caller should skip) when SE is unavailable — `material` is
    /// encrypted via the default (SE-backed) `Manager.Crypto()`, same as production.
    private func makeProfile(identifier: String, publicKey: Data, using crypto: Manager.Crypto) throws -> Contact.Profile? {
        guard let encrypted = try crypto.encrypt(data: publicKey) else { return nil }
        let profile = Contact.Profile(
            identifier: identifier, givenName: "", familyName: "", middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        profile.contactPublicKeys = [Contact.Profile.Key(material: encrypted, owner: Data(), date: Data())]
        return profile
    }

    // Regression for the group-review finding: encryptGroupBundle must not include a
    // contact Secure Mode considers hidden at the current depth, even when that
    // contact's identifier is still present in the group's stored member list — group
    // membership and per-contact visibility (visibleThroughDepth) are independent,
    // unsynchronized state, so a member reclassified as sensitive after being added
    // to a group must still be excluded at send time.
    @Test func excludesSensitiveMember_evenWhenPresentInGroupMemberList() throws {
        let realCrypto = Manager.Crypto()
        let cm = try self.makeContactManager()

        let visibleID = UUID().uuidString
        guard let visibleProfile = try self.makeProfile(
            identifier: visibleID, publicKey: try TestKeyManager().retrieveIdentity(), using: realCrypto
        ) else { print("⚠︎ Skipping — SE unavailable"); return }
        try cm.insertProfile(visibleProfile)

        let hiddenID = UUID().uuidString
        guard let hiddenProfile = try self.makeProfile(
            identifier: hiddenID, publicKey: try TestKeyManager().retrieveIdentity(), using: realCrypto
        ) else { return }
        // Non-decryptable field — isVisible() takes the conservative-exclusion path,
        // hiding this contact at every depth without needing a real classification flow.
        hiddenProfile.visibleThroughDepth = Data([0xFF, 0xFE])
        try cm.insertProfile(hiddenProfile)

        let group = try cm.createGroup(name: "Mixed")
        try group.addMember(visibleID, atDepth: 0)
        try group.addMember(hiddenID, atDepth: 0)

        let encoded = try cm.encryptGroupBundle(basket: Basket(files: []), groupID: try #require(group.readID()))
        let bundle  = try OccultaBundle.decoded(from: encoded)

        #expect(bundle.group?.recipients.count == 1,
                "sensitive member must be excluded even though present in the group's member list")
    }

    // Sanity check for the same fix: a group made up entirely of sensitive members
    // must fail with groupHasNoMembers rather than silently sending to nobody or
    // falling through to the pre-fix behavior.
    @Test func allMembersSensitive_throwsGroupHasNoMembers() throws {
        let realCrypto = Manager.Crypto()
        let cm = try self.makeContactManager()

        let hiddenID = UUID().uuidString
        guard let hiddenProfile = try self.makeProfile(
            identifier: hiddenID, publicKey: try TestKeyManager().retrieveIdentity(), using: realCrypto
        ) else { print("⚠︎ Skipping — SE unavailable"); return }
        hiddenProfile.visibleThroughDepth = Data([0xFF, 0xFE])
        try cm.insertProfile(hiddenProfile)

        let group = try cm.createGroup(name: "AllHidden")
        try group.addMember(hiddenID, atDepth: 0)

        #expect(throws: ContactManager.Errors.groupHasNoMembers) {
            try cm.encryptGroupBundle(basket: Basket(files: []), groupID: try #require(group.readID()))
        }
    }
}

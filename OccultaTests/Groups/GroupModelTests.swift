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
import CryptoKit
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

// MARK: - Group — purgeMembersFromDuressDepths

@Suite("Group — purgeMembersFromDuressDepths")
@MainActor struct GroupPurgeMembersFromDuressDepthsTests {

    @Test func removesOnlyGivenIdentifiers_keepsRealLayerAndOtherDuressMembers() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx   = ModelContext(try makeContainer())
        let group = try Group(name: "Purge")
        ctx.insert(group)

        let realID     = UUID().uuidString
        let staleID     = UUID().uuidString
        let unrelatedID = UUID().uuidString
        try group.addMember(realID,     atDepth: 0)
        try group.addMember(staleID,     atDepth: 1)
        try group.addMember(unrelatedID, atDepth: 1)
        try group.addMember(staleID,     atDepth: 5)
        try group.addMember(unrelatedID, atDepth: 5)

        try group.purgeMembersFromDuressDepths([staleID])

        #expect(group.members(atDepth: 0) == [realID])
        #expect(group.members(atDepth: 1) == [unrelatedID])
        #expect(group.members(atDepth: 5) == [unrelatedID])
    }

    // Regression guard: a diff that shows only the touched depths changing (real layer
    // untouched) would itself reveal that a duress-only purge just happened.
    @Test func reencryptsRealLayerSlots_evenThoughMembershipUnchanged() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx   = ModelContext(try makeContainer())
        let group = try Group(name: "Purge")
        ctx.insert(group)

        try group.addMember(UUID().uuidString, atDepth: 0)
        let beforeReal = group.realMemberSlots

        try group.purgeMembersFromDuressDepths([UUID().uuidString])

        #expect(beforeReal != group.realMemberSlots)
        #expect(group.members(atDepth: 0).count == 1)
    }

    @Test func onGroupWithNoMatchingMembers_isNoOpAndSucceeds() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx   = ModelContext(try makeContainer())
        let group = try Group(name: "Empty")
        ctx.insert(group)

        try group.purgeMembersFromDuressDepths([UUID().uuidString])

        #expect(group.members(atDepth: 0).isEmpty)
        #expect(group.members(atDepth: 1).isEmpty)
    }
}

// MARK: - ContactManager — classification purges group duress membership

@Suite("ContactManager — classification purges group duress membership")
@MainActor struct ClassificationPurgesGroupDuressTests {

    private func makeContactManager() throws -> ContactManager {
        let container = try makeContainer()
        let security  = try Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        return ContactManager(modelContainer: container, security: security)
    }

    private func insertPlainProfile(identifier: String, in cm: ContactManager) throws {
        let profile = Contact.Profile(
            identifier: identifier, givenName: "", familyName: "", middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        try cm.insertProfile(profile)
    }

    // Regression for the stale-duress-membership gap: reclassifying a contact as
    // sensitive from the real layer (depth 0) — the one depth guaranteed not to be
    // under coercion — must remove exactly that contact from every group's duress-depth
    // membership, while leaving every other (unrelated) duress-depth member untouched.
    // A prior version of this cleanup wiped *all* duress-depth membership on any
    // depth-0 hide, destroying unrelated decoy content a user may have built by hand.
    @Test func setVisibility_sensitiveAtDepth0_purgesThatContactOnly_keepsOtherDuressMembers() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let cm = try self.makeContactManager()
        let identifier = UUID().uuidString
        try self.insertPlainProfile(identifier: identifier, in: cm)

        let group = try cm.createGroup(name: "G")
        let unrelatedID = UUID().uuidString
        try group.addMember(identifier, atDepth: 1)
        try group.addMember(unrelatedID, atDepth: 1)

        try cm.setVisibility(for: identifier, isSensitive: true)

        #expect(group.members(atDepth: 1) == [unrelatedID])
    }

    // Marking a contact safe hides no one — must not purge any duress membership.
    @Test func setVisibility_safeAtDepth0_doesNotPurge_butStillRefreshesCiphertext() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let cm = try self.makeContactManager()
        let identifier = UUID().uuidString
        try self.insertPlainProfile(identifier: identifier, in: cm)

        let group = try cm.createGroup(name: "G")
        let duressMemberID = UUID().uuidString
        try group.addMember(duressMemberID, atDepth: 1)
        let beforeDuress = group.duressMemberSlots

        try cm.setVisibility(for: identifier, isSensitive: false)

        #expect(group.members(atDepth: 1) == [duressMemberID])
        // Camouflage: ciphertext must still change even though nothing was purged —
        // otherwise "did the purge run" would be a keyless, forensically-visible signal.
        #expect(beforeDuress != group.duressMemberSlots)
    }

    // Reclassification from a duress depth can't be guaranteed non-coerced the way
    // depth 0 can — must not trigger the purge. Ciphertext must still refresh.
    @Test func setVisibility_sensitiveFromDuressDepth_doesNotPurge_butStillRefreshesCiphertext() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let cm = try self.makeContactManager()
        let identifier = UUID().uuidString
        try self.insertPlainProfile(identifier: identifier, in: cm)

        let group = try cm.createGroup(name: "G")
        let duressMemberID = UUID().uuidString
        try group.addMember(duressMemberID, atDepth: 2)
        let beforeDeeper = group.deeperMemberSlots

        cm.security.applyVerifyState(for: .duress)
        #expect(cm.security.currentDepth == 1)

        try cm.setVisibility(for: identifier, isSensitive: true)

        #expect(group.members(atDepth: 2) == [duressMemberID])
        #expect(beforeDeeper != group.deeperMemberSlots)
    }

    @Test func saveClassification_hidingSomeone_atDepth0_purgesThatContactOnly_keepsOtherDuressMembers() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let cm = try self.makeContactManager()
        let safeID      = UUID().uuidString
        let sensitiveID = UUID().uuidString
        try self.insertPlainProfile(identifier: safeID, in: cm)
        try self.insertPlainProfile(identifier: sensitiveID, in: cm)

        let group = try cm.createGroup(name: "G")
        let unrelatedID = UUID().uuidString
        try group.addMember(sensitiveID, atDepth: 3)
        try group.addMember(unrelatedID, atDepth: 3)

        try cm.saveClassification(safeIDs: [safeID])

        #expect(group.members(atDepth: 3) == [unrelatedID])
    }

    @Test func saveClassification_allSafe_doesNotPurge_butStillRefreshesCiphertext() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let cm = try self.makeContactManager()
        let safeID = UUID().uuidString
        try self.insertPlainProfile(identifier: safeID, in: cm)

        let group = try cm.createGroup(name: "G")
        let duressMemberID = UUID().uuidString
        try group.addMember(duressMemberID, atDepth: 1)
        let beforeDuress = group.duressMemberSlots

        try cm.saveClassification(safeIDs: [safeID])

        #expect(group.members(atDepth: 1) == [duressMemberID])
        #expect(beforeDuress != group.duressMemberSlots)
    }
}

// MARK: - Group — refreshCiphertext / purgeMember

@Suite("Group — refreshCiphertext and purgeMember")
@MainActor struct GroupCiphertextHygieneTests {

    @Test func refreshCiphertext_changesEveryDepth_keepsAllMembership() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx   = ModelContext(try makeContainer())
        let group = try Group(name: "Refresh")
        ctx.insert(group)

        let realID   = UUID().uuidString
        let duressID = UUID().uuidString
        let deeperID = UUID().uuidString
        try group.addMember(realID,   atDepth: 0)
        try group.addMember(duressID, atDepth: 1)
        try group.addMember(deeperID, atDepth: 4)

        let beforeReal   = group.realMemberSlots
        let beforeDuress = group.duressMemberSlots
        let beforeDeeper = group.deeperMemberSlots

        try group.refreshCiphertext()

        #expect(beforeReal   != group.realMemberSlots)
        #expect(beforeDuress != group.duressMemberSlots)
        #expect(beforeDeeper != group.deeperMemberSlots)

        #expect(group.members(atDepth: 0) == [realID])
        #expect(group.members(atDepth: 1) == [duressID])
        #expect(group.members(atDepth: 4) == [deeperID])
    }

    @Test func purgeMember_removesFromEveryDepth_includingRealLayer() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx   = ModelContext(try makeContainer())
        let group = try Group(name: "Purge")
        ctx.insert(group)

        let target = UUID().uuidString
        try group.addMember(target, atDepth: 0)
        try group.addMember(target, atDepth: 1)
        try group.addMember(target, atDepth: 3)

        try group.purgeMember(target)

        #expect(group.members(atDepth: 0).isEmpty)
        #expect(group.members(atDepth: 1).isEmpty)
        #expect(group.members(atDepth: 3).isEmpty)
    }

    @Test func purgeMember_leavesOtherMembersUntouched() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx   = ModelContext(try makeContainer())
        let group = try Group(name: "Purge")
        ctx.insert(group)

        let target   = UUID().uuidString
        let bystander = UUID().uuidString
        try group.addMember(target, atDepth: 1)
        try group.addMember(bystander, atDepth: 1)

        try group.purgeMember(target)

        #expect(group.members(atDepth: 1) == [bystander])
    }

    // Regression guard: touching only the depths where the identifier was actually
    // found would reveal which depths held this contact. Every depth must re-encrypt
    // regardless of whether a removal happened there.
    @Test func purgeMember_reencryptsEveryDepth_evenWhereNotPresent() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx   = ModelContext(try makeContainer())
        let group = try Group(name: "Purge")
        ctx.insert(group)

        try group.addMember(UUID().uuidString, atDepth: 0)
        let beforeReal   = group.realMemberSlots
        let beforeDuress = group.duressMemberSlots
        let beforeDeeper = group.deeperMemberSlots

        // Not a member of this group at any depth.
        try group.purgeMember(UUID().uuidString)

        #expect(beforeReal   != group.realMemberSlots)
        #expect(beforeDuress != group.duressMemberSlots)
        #expect(beforeDeeper != group.deeperMemberSlots)
    }
}

// MARK: - Group — keyed batch re-encryption (derive-once path)
//
// Covers the fix for the multi-second visibility-toggle hang: `members(atDepth:)`
// discovers real members by attempting `.decrypt()` on every slot, which previously
// re-derived the hybrid key from Secure Enclave + Keychain per slot. These tests verify
// the `usingKey:` overloads — which reuse one caller-derived key across a whole batch —
// behave identically to the original per-call-derivation path, and that a threading
// mistake (the danger this design flags: a wrong key silently reads back zero members,
// which then gets written as the new ground truth) is at least verified to not crash and
// to produce the expected empty result rather than something worse.

@Suite("Group — keyed batch re-encryption")
@MainActor struct GroupKeyedReencryptionTests {

    private func requireKey() throws -> SymmetricKey {
        guard let key = try Manager.Key().createHybridLocalEncryptionKey() else {
            throw GroupError.keyUnavailable
        }
        return key
    }

    // MARK: Parity — usingKey: variants must match the no-key convenience overloads

    @Test func refreshCiphertext_usingKey_matchesNoKeyOverload() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx   = ModelContext(try makeContainer())
        let group = try Group(name: "Refresh")
        ctx.insert(group)

        let realID   = UUID().uuidString
        let duressID = UUID().uuidString
        let deeperID = UUID().uuidString
        try group.addMember(realID,   atDepth: 0)
        try group.addMember(duressID, atDepth: 1)
        try group.addMember(deeperID, atDepth: 4)

        let key = try requireKey()
        try group.refreshCiphertext(usingKey: key)

        #expect(group.members(atDepth: 0) == [realID])
        #expect(group.members(atDepth: 1) == [duressID])
        #expect(group.members(atDepth: 4) == [deeperID])
    }

    @Test func purgeMember_usingKey_matchesNoKeyOverload() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx   = ModelContext(try makeContainer())
        let group = try Group(name: "Purge")
        ctx.insert(group)

        let target    = UUID().uuidString
        let bystander = UUID().uuidString
        try group.addMember(target, atDepth: 1)
        try group.addMember(bystander, atDepth: 1)

        let key = try requireKey()
        try group.purgeMember(target, usingKey: key)

        #expect(group.members(atDepth: 1) == [bystander])
    }

    @Test func purgeMembersFromDuressDepths_usingKey_matchesNoKeyOverload() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx   = ModelContext(try makeContainer())
        let group = try Group(name: "Purge")
        ctx.insert(group)

        let realID      = UUID().uuidString
        let staleID      = UUID().uuidString
        let unrelatedID  = UUID().uuidString
        try group.addMember(realID,     atDepth: 0)
        try group.addMember(staleID,     atDepth: 1)
        try group.addMember(unrelatedID, atDepth: 1)

        let key = try requireKey()
        try group.purgeMembersFromDuressDepths([staleID], usingKey: key)

        #expect(group.members(atDepth: 0) == [realID])
        #expect(group.members(atDepth: 1) == [unrelatedID])
    }

    @Test func members_atDepth_usingKey_matchesNoKeyOverload() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx   = ModelContext(try makeContainer())
        let group = try Group(name: "Read")
        ctx.insert(group)

        let id = UUID().uuidString
        try group.addMember(id, atDepth: 0)

        let key = try requireKey()
        #expect(group.members(atDepth: 0, usingKey: key) == group.members(atDepth: 0))
    }

    // MARK: Defensive — a wrong key must not crash, and must not silently "succeed"

    @Test func members_atDepth_usingKey_withWrongKey_returnsEmpty_notCrash() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx   = ModelContext(try makeContainer())
        let group = try Group(name: "WrongKey")
        ctx.insert(group)

        try group.addMember(UUID().uuidString, atDepth: 0)
        #expect(!group.members(atDepth: 0).isEmpty, "sanity check: real key reads back the member")

        let wrongKey = SymmetricKey(size: .bits256)
        #expect(
            group.members(atDepth: 0, usingKey: wrongKey).isEmpty,
            "A mismatched key must fail closed (no members found), not crash and not return real data"
        )
    }

    // MARK: Fail-loud — derivation failure must abort, not silently skip the refresh

    @Test func refreshCiphertext_throwsKeyUnavailable_whenSEUnavailable() throws {
        guard !secureEnclaveAvailable() else { print("⚠︎ Skipping — requires an SE-unavailable environment"); return }
        let ctx   = ModelContext(try makeContainer())
        let group = try Group(name: "NoSE")
        ctx.insert(group)

        #expect(throws: GroupError.keyUnavailable) {
            try group.refreshCiphertext()
        }
    }

    @Test func addMember_throwsKeyUnavailable_whenSEUnavailable() throws {
        guard !secureEnclaveAvailable() else { print("⚠︎ Skipping — requires an SE-unavailable environment"); return }
        let ctx   = ModelContext(try makeContainer())
        let group = try Group(name: "NoSE")
        ctx.insert(group)

        #expect(throws: GroupError.keyUnavailable) {
            try group.addMember(UUID().uuidString, atDepth: 0)
        }
    }
}

// MARK: - ContactManager — deleteContact purges group membership

@Suite("ContactManager — deleteContact purges group membership")
@MainActor struct DeleteContactPurgesGroupsTests {

    private func makeContactManager() throws -> ContactManager {
        let container = try makeContainer()
        let security  = try Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        return ContactManager(modelContainer: container, security: security)
    }

    private func insertPlainProfile(identifier: String, in cm: ContactManager) throws {
        let profile = Contact.Profile(
            identifier: identifier, givenName: "", familyName: "", middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        try cm.insertProfile(profile)
    }

    @Test func deleteContact_purgesMemberFromEveryDepth() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let cm = try self.makeContactManager()
        let identifier = UUID().uuidString
        try self.insertPlainProfile(identifier: identifier, in: cm)

        let group = try cm.createGroup(name: "G")
        try group.addMember(identifier, atDepth: 0)
        try group.addMember(identifier, atDepth: 2)

        try cm.deleteContact(identifier: identifier)

        #expect(group.members(atDepth: 0).isEmpty)
        #expect(group.members(atDepth: 2).isEmpty)
    }

    // Deletion is unambiguous everywhere — unlike classification, purging is safe at
    // any depth, since it only ever touches the one deleted identifier.
    @Test func deleteContact_fromDuressDepth_stillPurgesMember() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let cm = try self.makeContactManager()
        let identifier = UUID().uuidString
        try self.insertPlainProfile(identifier: identifier, in: cm)

        let group = try cm.createGroup(name: "G")
        try group.addMember(identifier, atDepth: 1)

        cm.security.applyVerifyState(for: .duress)
        #expect(cm.security.currentDepth == 1)

        try cm.deleteContact(identifier: identifier)

        #expect(group.members(atDepth: 1).isEmpty)
    }

    @Test func deleteContact_leavesOtherGroupMembersIntact() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let cm = try self.makeContactManager()
        let target    = UUID().uuidString
        let bystander = UUID().uuidString
        try self.insertPlainProfile(identifier: target, in: cm)
        try self.insertPlainProfile(identifier: bystander, in: cm)

        let group = try cm.createGroup(name: "G")
        try group.addMember(target, atDepth: 0)
        try group.addMember(bystander, atDepth: 0)

        try cm.deleteContact(identifier: target)

        #expect(group.members(atDepth: 0) == [bystander])
    }

    // Confirms the wiring, and the item 3 consolidation's design decision: deleting
    // a contact needs no separate global-trustee purge step at all —
    // ShardCustodyManager.purgeCustody(for:) no longer touches trustee state (see
    // the shard-custody bug doc, item 3). globalTrusteeDepth lives on the contact's
    // own row, which deleteContact soft-deletes, and every trustee read already
    // excludes soft-deleted rows.
    @Test func deleteContact_makesGlobalTrusteeDesignationUnreachable() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }

        let schema = Schema([
            Group.self,
            Contact.Profile.self, Contact.Profile.PhoneNumber.self, Contact.Profile.EmailAddress.self,
            Contact.Profile.PostalAddress.self, Contact.Profile.URLAddress.self, Contact.Profile.Key.self,
            VaultEntry.self, CustodyShard.self, ReconstructShard.self,
            PendingShardDistribute.self, PendingShardStatusUpdate.self, PotentiallyLostShard.self,
            GlobalShardConfig.self
        ])
        let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
        let km        = TestKeyManager()
        let security  = try Manager.Security(modelContainer: container, keyManager: km)
        let cm        = ContactManager(modelContainer: container, security: security)
        let custody   = ShardCustodyManager(modelContainer: container, keyManager: km)
        let vault     = VaultManager(modelContainer: container, keyManager: km)

        let target = UUID().uuidString
        let other  = UUID().uuidString
        try self.insertPlainProfile(identifier: target, in: cm)
        try self.insertPlainProfile(identifier: other, in: cm)
        try cm.saveGlobalTrusteeDepth(selectedIDs: [target, other])
        #expect(cm.isGlobalTrustee(target))
        #expect(cm.isGlobalTrustee(other))

        try cm.deleteContact(identifier: target, vaultManager: vault, shardCustodyManager: custody)

        #expect(!cm.isGlobalTrustee(target), "a deleted contact's trustee designation must become unreachable")
        #expect(cm.isGlobalTrustee(other), "an unrelated contact's designation must survive")
    }
}

// MARK: - Manager.Security — Contact.Profile depth visibility (isDisplayable/isVisible)
//
// Covers Gap 2 items 1+2 of the shard-custody doc — Vault+Tab.swift's custodian
// list and VaultGlobalTrustees.swift's picker both newly gate on isDisplayable(_:),
// which had no direct test coverage of its own before this (only an indirect,
// shallow check via isSensitive's default-false case).

@Suite("Manager.Security — Contact.Profile depth visibility")
@MainActor struct ContactDepthVisibilityTests {

    private func makeContactManager() throws -> ContactManager {
        let container = try makeContainer()
        let security  = try Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        return ContactManager(modelContainer: container, security: security)
    }

    private func insertPlainProfile(identifier: String, in cm: ContactManager) throws {
        let profile = Contact.Profile(
            identifier: identifier, givenName: "", familyName: "", middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        try cm.insertProfile(profile)
    }

    @Test func safeContact_visibleAtEveryDepth() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let cm = try self.makeContactManager()
        let id = UUID().uuidString
        try self.insertPlainProfile(identifier: id, in: cm)
        try cm.setVisibility(for: id, isSensitive: false) // safe → Int.max

        let contact = try cm.fetchContact(by: id)!
        cm.security.applyVerifyState(for: .normal(depth: 0))
        #expect(contact.isVisible(atDepth: cm.security.currentDepth))
        cm.security.applyVerifyState(for: .normal(depth: 5))
        #expect(contact.isVisible(atDepth: cm.security.currentDepth), "a safe contact must stay visible at every depth")
    }

    @Test func sensitiveContact_visibleThroughClassificationDepth_hiddenBeyond() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let cm = try self.makeContactManager()
        let id = UUID().uuidString
        try self.insertPlainProfile(identifier: id, in: cm)

        cm.security.applyVerifyState(for: .normal(depth: 2))
        try cm.setVisibility(for: id, isSensitive: true) // stamps ceiling = currentDepth = 2

        let contact = try cm.fetchContact(by: id)!
        cm.security.applyVerifyState(for: .normal(depth: 0))
        #expect(contact.isVisible(atDepth: cm.security.currentDepth), "still visible at a shallower depth than its classification ceiling")
        cm.security.applyVerifyState(for: .normal(depth: 2))
        #expect(contact.isVisible(atDepth: cm.security.currentDepth), "visible at its own classification depth")
        cm.security.applyVerifyState(for: .normal(depth: 3))
        #expect(!contact.isVisible(atDepth: cm.security.currentDepth), "hidden beyond its classification depth")
    }

    @Test func unclassifiedContact_nilVisibleThroughDepth_alwaysVisible() throws {
        let cm = try self.makeContactManager()
        let id = UUID().uuidString
        try self.insertPlainProfile(identifier: id, in: cm)

        let contact = try cm.fetchContact(by: id)!
        #expect(contact.visibleThroughDepth == nil)
        cm.security.applyVerifyState(for: .normal(depth: 4))
        #expect(contact.isVisible(atDepth: cm.security.currentDepth), "a never-classified contact (nil visibleThroughDepth) must stay visible everywhere")
    }
}

// MARK: - ShardCustodyManager — merge-not-overwrite trustee save (removed)
//
// Covered the sharp edge in Gap 2 item 2: once VaultGlobalTrustees only showed
// currently-visible candidates, saving just that subset would silently delete
// every currently-hidden trustee. saveGlobalShardConfig(mergingVisibleSelection:isVisible:)
// existed specifically to prevent that, on the old flat GlobalShardConfig.trusteeIDs
// storage. Removed along with that method as part of item 3's consolidation onto
// Contact.Profile.globalTrusteeDepth (see the shard-custody bug doc) — each contact's
// field is independent, so there is no flat list left to corrupt with a partial save.

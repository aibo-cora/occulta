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

    @Test func constants_slotSize_is64() {
        #expect(Group.slotSize == 64)
    }

    @Test func freshFillerArray_count_is32() {
        #expect(Group.freshFillerArray().count == Group.slotCount)
    }

    @Test func freshFillerArray_allSlots_are64bytes() {
        for slot in Group.freshFillerArray() {
            #expect(slot.count == Group.slotSize)
        }
    }

    @Test func freshFillerArray_isRandom_twoCallsDiffer() {
        let a = Group.freshFillerArray()
        let b = Group.freshFillerArray()
        #expect(a != b, "Two fresh filler arrays must differ — each slot is cryptographically random")
    }

    @Test func twoFreshFillerArrays_areIndependent() {
        // Real and duress arrays initialised from independent freshFillerArray() calls must differ.
        let real   = Group.freshFillerArray()
        let duress = Group.freshFillerArray()
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
        try group.addMember(id, in: .normal)
        #expect(group.members(in: .normal).contains(id))
    }

    @Test func addMember_doesNotAppearInOtherLayer() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx = ModelContext(try makeContainer())
        let group = try Group(name: "Friends")
        ctx.insert(group)

        try group.addMember(UUID().uuidString, in: .normal)
        #expect(group.members(in: .duress).isEmpty, "Real member must not leak into duress layer")
    }

    @Test func addMember_allSlotsRemain64bytes() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx = ModelContext(try makeContainer())
        let group = try Group(name: "Family")
        ctx.insert(group)

        try group.addMember(UUID().uuidString, in: .normal)

        #expect(group.realMemberSlots.count == Group.slotCount)
        for slot in group.realMemberSlots {
            #expect(slot.count == Group.slotSize)
        }
    }

    @Test func addMember_fullRecompute_bothArraysChange() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx = ModelContext(try makeContainer())
        let group = try Group(name: "Team")
        ctx.insert(group)

        let beforeReal   = group.realMemberSlots
        let beforeDuress = group.duressMemberSlots
        try group.addMember(UUID().uuidString, in: .normal)
        // Both arrays must change — if only the target changed, a DB diff would
        // reveal which layer was written.
        #expect(beforeReal   != group.realMemberSlots)
        #expect(beforeDuress != group.duressMemberSlots)
    }

    @Test func removeMember_noLongerReadable() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx = ModelContext(try makeContainer())
        let group = try Group(name: "Crew")
        ctx.insert(group)

        let id = UUID().uuidString
        try group.addMember(id, in: .normal)
        try group.removeMember(id, in: .normal)
        #expect(group.members(in: .normal).isEmpty)
    }

    @Test func addMember_duplicate_isIdempotent() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx = ModelContext(try makeContainer())
        let group = try Group(name: "Club")
        ctx.insert(group)

        let id = UUID().uuidString
        try group.addMember(id, in: .normal)
        try group.addMember(id, in: .normal)
        #expect(group.members(in: .normal).count == 1)
    }

    @Test func addMember_exceeds32_throwsCapacityExceeded() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx = ModelContext(try makeContainer())
        let group = try Group(name: "Large")
        ctx.insert(group)

        for _ in 0..<Group.slotCount {
            try group.addMember(UUID().uuidString, in: .normal)
        }
        #expect(throws: GroupError.capacityExceeded) {
            try group.addMember(UUID().uuidString, in: .normal)
        }
    }

    @Test func duressLayer_independentFromRealLayer() throws {
        guard secureEnclaveAvailable() else { print("⚠︎ Skipping — SE unavailable"); return }
        let ctx = ModelContext(try makeContainer())
        let group = try Group(name: "Dual")
        ctx.insert(group)

        let realID   = UUID().uuidString
        let duressID = UUID().uuidString
        try group.addMember(realID,   in: .normal)
        try group.addMember(duressID, in: .duress)

        #expect(group.members(in: .normal) == [realID])
        #expect(group.members(in: .duress) == [duressID])
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

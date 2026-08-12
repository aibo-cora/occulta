//
//  GroupKeyRotationTests.swift
//  OccultaTests
//
//  Regression coverage for Bug 75: `Group` rows were never re-keyed during the Secure
//  Mode local-DB key rotation.
//
//  Activation re-encrypted contacts, vault depth stamps, and drafts under the staged key,
//  then deleted the superseded key in Step 11. `Group` was in none of those passes, so
//  every group stayed sealed under a key that no longer existed — name, ID, creation
//  date, and all 32 depths of membership permanently unreadable. Because every UI path
//  resolves a group through `readID()`, the dead rows were also unreachable and
//  undeletable: the Groups tab showed a bare "N groups" count and nothing else.
//
//  These tests exercise `Group.reencrypt(from:to:)` directly rather than driving a full
//  activation, which needs Secure Mode state and a device. They require working key
//  derivation to build the group in the first place, and skip where it is unavailable.
//

import Testing
import Foundation
import CryptoKit
@testable import Occulta

// MARK: - Helpers

private func canonicalKey() -> SymmetricKey? {
    try? Manager.Key().createHybridLocalEncryptionKey()
}

// MARK: - Tests

@Suite("Bug 75 — Group survives key rotation")
struct GroupKeyRotationTests {

    /// The core regression: everything a group holds must be readable under the new key
    /// and unreadable under the old one, exactly as a contact's fields are.
    @Test("Name, ID and membership survive a rotation")
    func groupSurvivesRotation() throws {
        let oldKey = try #require(canonicalKey())
        let group  = try Group(name: "Climbing Club")
        try group.addMember("alice", atDepth: 0)
        try group.addMember("bob",   atDepth: 0)
        try group.addMember("decoy", atDepth: 1)

        let originalID = try #require(group.readID())

        let newKey = SymmetricKey(size: .bits256)
        try group.reencrypt(from: oldKey, to: newKey)

        // Readable under the new key.
        let idPlain = try #require(group.encryptedID?.decrypt(using: newKey))
        #expect(UUID(uuidString: String(decoding: idPlain, as: UTF8.self)) == originalID)

        let namePlain = try #require(group.encryptedName?.decrypt(using: newKey))
        #expect(String(decoding: namePlain, as: UTF8.self) == "Climbing Club")

        #expect(Set(group.members(atDepth: 0, usingKey: newKey)) == ["alice", "bob"])
        #expect(group.members(atDepth: 1, usingKey: newKey) == ["decoy"])

        // And no longer readable under the old one — the rotation actually moved it.
        #expect(group.encryptedID?.decrypt(using: oldKey) == nil)
        #expect(group.members(atDepth: 0, usingKey: oldKey).isEmpty)
    }

    /// Bug 73 gave depths 2+ their own independent membership. A rotation must carry every
    /// depth across, not just the two that predate `deeperMemberSlots`.
    @Test("Independent membership at deeper duress depths survives")
    func deeperDepthsSurvive() throws {
        let oldKey = try #require(canonicalKey())
        let group  = try Group(name: "Layers")
        try group.addMember("real",    atDepth: 0)
        try group.addMember("duress1", atDepth: 1)
        try group.addMember("duress2", atDepth: 2)
        try group.addMember("duress7", atDepth: 7)

        let newKey = SymmetricKey(size: .bits256)
        try group.reencrypt(from: oldKey, to: newKey)

        #expect(group.members(atDepth: 0, usingKey: newKey) == ["real"])
        #expect(group.members(atDepth: 1, usingKey: newKey) == ["duress1"])
        #expect(group.members(atDepth: 2, usingKey: newKey) == ["duress2"])
        #expect(group.members(atDepth: 7, usingKey: newKey) == ["duress7"])
        // A depth never written stays empty rather than leaking another depth's members.
        #expect(group.members(atDepth: 5, usingKey: newKey).isEmpty)
    }

    /// Every depth's slot array must be rewritten, so a raw-DB diff cannot single out which
    /// depth held content. Same invariant `reencryptAllDepths` enforces for its other callers.
    @Test("Every depth's ciphertext changes, and slot geometry is preserved")
    func allDepthsRewrittenAndPadded() throws {
        let oldKey = try #require(canonicalKey())
        let group  = try Group(name: "Geometry")
        try group.addMember("only", atDepth: 0)

        let beforeReal   = group.realMemberSlots
        let beforeDuress = group.duressMemberSlots

        let newKey = SymmetricKey(size: .bits256)
        try group.reencrypt(from: oldKey, to: newKey)

        #expect(group.realMemberSlots   != beforeReal)
        #expect(group.duressMemberSlots != beforeDuress)

        #expect(group.realMemberSlots.count   == Group.slotCount)
        #expect(group.duressMemberSlots.count == Group.slotCount)
        #expect(group.deeperMemberSlots.count == Group.depthCount - 2)
        #expect(group.realMemberSlots.allSatisfy   { $0.count == Group.slotSize })
        #expect(group.duressMemberSlots.allSatisfy { $0.count == Group.slotSize })
        #expect(group.deeperMemberSlots.allSatisfy { $0.allSatisfy { $0.count == Group.slotSize } })
    }

    // Not covered: a pre-1.9.1 row whose `deeperMemberSlots` is still empty being padded by
    // the rotation. `deeperMemberSlots` is `private(set)`, which `@testable` does not
    // elevate, so that starting state cannot be constructed without adding a test-only
    // mutator to the model — production surface this does not justify. The padding call
    // itself is covered indirectly by `allDepthsRewrittenAndPadded`, which asserts the array
    // is full size afterward.

    /// An already-orphaned group carries nothing recoverable. Re-sealing it would only make
    /// a dead row look freshly edited, so it is left byte-identical and purged separately.
    @Test("An already-orphaned group is left untouched")
    func orphanedGroupUntouched() throws {
        let oldKey = try #require(canonicalKey())
        let group  = try Group(name: "Orphan")
        try group.addMember("gone", atDepth: 0)

        // Strand it: rotate to a key nobody holds, simulating the deleted canonical key.
        let lostKey = SymmetricKey(size: .bits256)
        try group.reencrypt(from: oldKey, to: lostKey)

        let strandedID    = group.encryptedID
        let strandedName  = group.encryptedName
        let strandedSlots = group.realMemberSlots

        // A later rotation cannot read it and must not rewrite it.
        let newKey = SymmetricKey(size: .bits256)
        try group.reencrypt(from: oldKey, to: newKey)

        #expect(group.encryptedID      == strandedID)
        #expect(group.encryptedName    == strandedName)
        #expect(group.realMemberSlots  == strandedSlots)
    }

    /// Two rotations back to back — the multi-layer case that strands metadata in Bug 76.
    @Test("A group survives consecutive rotations")
    func groupSurvivesConsecutiveRotations() throws {
        let oldKey = try #require(canonicalKey())
        let group  = try Group(name: "Chain")
        try group.addMember("alice", atDepth: 0)
        try group.addMember("decoy", atDepth: 1)

        let k2 = SymmetricKey(size: .bits256)
        let k3 = SymmetricKey(size: .bits256)
        try group.reencrypt(from: oldKey, to: k2)
        try group.reencrypt(from: k2,     to: k3)

        let namePlain = try #require(group.encryptedName?.decrypt(using: k3))
        #expect(String(decoding: namePlain, as: UTF8.self) == "Chain")
        #expect(group.members(atDepth: 0, usingKey: k3) == ["alice"])
        #expect(group.members(atDepth: 1, usingKey: k3) == ["decoy"])
    }
}

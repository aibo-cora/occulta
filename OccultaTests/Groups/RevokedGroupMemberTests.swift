//
//  RevokedGroupMemberTests.swift
//  OccultaTests
//
//  `Docs/Bugs/v2.1.0/Revoked-Contact-Stays-In-Group-With-No-Warning-And-Group-Send-Fails-Opaquely.md`:
//  `reset(identity:)` leaves a revoked contact in every group, and `encryptGroupBundle` then throws
//  `contactHasNoKeys` from pass 1, so no bundle is produced for any member.
//
//  Runs anywhere: software keys, no prekeys (the long-term path), no Enclave.
//

import Testing
import Foundation
@testable import Occulta
@testable import OccultaFormats

@MainActor
@Suite("A revoked member of a group", .serialized)
struct RevokedGroupMemberTests {

    /// A phone with a group of three contacts, each holding another phone's identity key.
    private struct Setup {
        let phone: CardPhone
        let ids: [String]
        let group: UUID
    }

    private func setup() throws -> Setup {
        let phone = try CardPhone()
        let ids = try (0..<3).map { _ -> String in
            let id = UUID().uuidString
            try phone.addOrdinary(try CardPhone(), as: id)
            return id
        }
        let group = try phone.run { () -> UUID in
            let group = try phone.cm.createGroup(name: "G")
            for id in ids { try group.addMember(id, atDepth: 0) }
            return try #require(group.readID())
        }
        return Setup(phone: phone, ids: ids, group: group)
    }

    @discardableResult
    private func send(_ s: Setup, skipping: Set<String> = []) throws -> Data {
        try s.phone.run {
            try s.phone.cm.encryptGroupBundle(basket: CardPhone.basket("x"), groupID: s.group, skipping: skipping)
        }
    }

    private func recipientCount(_ bundle: Data) throws -> Int {
        try #require(try OccultaBundle.decoded(from: bundle).group).recipients.count
    }

    private func revoke(_ s: Setup, _ indexes: Int...) throws {
        try s.phone.run { for i in indexes { try s.phone.cm.reset(identity: s.ids[i]) } }
    }

    @Test("Baseline: a group of three contacts with keys is sent to")
    func baseline() throws {
        let s = try self.setup()
        try self.send(s)
    }

    @Test("Revoking leaves the contact in the group's members at the real depth")
    func revokeKeepsMembership() throws {
        let s = try self.setup()

        try s.phone.run { try s.phone.cm.reset(identity: s.ids[0]) }

        let members = try s.phone.run { try #require(try s.phone.cm.group(withID: s.group)).members(atDepth: 0) }
        #expect(Set(members) == Set(s.ids), "today: nothing removes or marks the revoked member")
    }

    @Test("A send with a revoked member stops and names exactly that member")
    func revokedMemberStopsTheSend() throws {
        let s = try self.setup()
        try self.revoke(s, 0)

        #expect(throws: ContactManager.Errors.groupMembersWithoutKeys([s.ids[0]])) { try self.send(s) }
    }

    @Test("Every unexcused member without a key is named, and an excused one is not")
    func namesOnlyTheUnexcused() throws {
        let s = try self.setup()
        try self.revoke(s, 0, 1)

        #expect(throws: ContactManager.Errors.groupMembersWithoutKeys([s.ids[1]])) {
            try self.send(s, skipping: [s.ids[0]])
        }
    }

    @Test("Skipping the revoked member sends to the others only")
    func skippingSendsToTheRest() throws {
        let s = try self.setup()
        try self.revoke(s, 0)

        let bundle = try self.send(s, skipping: [s.ids[0]])

        #expect(try self.recipientCount(bundle) == 2)
    }

    @Test("A skip entry never drops a member who can receive")
    func skipIgnoresMembersWithKeys() throws {
        let s = try self.setup()
        try self.revoke(s, 0)

        let bundle = try self.send(s, skipping: [s.ids[0], s.ids[1], s.ids[2]])

        #expect(try self.recipientCount(bundle) == 2, "ids[1] and ids[2] hold keys, so they stay")
    }

    @Test("A skip entry alone changes nothing when no one is revoked")
    func skipWithNoRevokedChangesNothing() throws {
        let s = try self.setup()

        let bundle = try self.send(s, skipping: [s.ids[0]])

        #expect(try self.recipientCount(bundle) == 3)
    }

    @Test("When every member is revoked and skipped, there is no one to send to")
    func everyoneSkippedHasNoMembers() throws {
        let s = try self.setup()
        try self.revoke(s, 0, 1, 2)

        #expect(throws: ContactManager.Errors.groupHasNoMembers) { try self.send(s, skipping: Set(s.ids)) }
    }

    @Test("hasCurrentKey is false after a revoke and true again after a fresh exchange")
    func hasCurrentKeyFollowsTheKey() throws {
        let s = try self.setup()
        let before = try s.phone.run { try s.phone.contact(s.ids[0]).hasCurrentKey }
        try self.revoke(s, 0)
        let revoked = try s.phone.run { try s.phone.contact(s.ids[0]).hasCurrentKey }

        #expect(before)
        #expect(!revoked)
    }

    // MARK: The groups the Revoke Key screen names

    @Test("groupNames lists every group the contact is in at the depth, sorted, and no other")
    func groupNamesListsMembership() throws {
        let s = try self.setup()          // "G", with all three contacts
        try s.phone.run {
            let other = try s.phone.cm.createGroup(name: "Family")
            try other.addMember(s.ids[0], atDepth: 0)
            let without = try s.phone.cm.createGroup(name: "Work")
            try without.addMember(s.ids[1], atDepth: 0)
        }

        let names = try s.phone.run { try s.phone.cm.groupNames(containing: s.ids[0], atDepth: 0) }

        #expect(names == ["Family", "G"])
    }

    @Test("groupNames reads only the depth asked for")
    func groupNamesIsPerDepth() throws {
        let s = try self.setup()
        try s.phone.run {
            let decoy = try s.phone.cm.createGroup(name: "Decoy")
            try decoy.addMember(s.ids[0], atDepth: 1)
        }

        let byDepth = try s.phone.run { try (0...2).map { try s.phone.cm.groupNames(containing: s.ids[0], atDepth: $0) } }

        #expect(byDepth == [["G"], ["Decoy"], []])
    }

    @Test("groupNames is empty for a contact in no group, and when there are no groups")
    func groupNamesEmpty() throws {
        let s = try self.setup()
        let stranger = UUID().uuidString
        let none = try s.phone.run { try s.phone.cm.groupNames(containing: stranger, atDepth: 0) }
        #expect(none == [])

        let bare = try CardPhone()
        let noGroups = try bare.run { try bare.cm.groupNames(containing: stranger, atDepth: 0) }
        #expect(noGroups == [])
    }

    @Test("groupNames still lists a group after the contact's key is revoked")
    func groupNamesAfterRevoke() throws {
        let s = try self.setup()
        try s.phone.run { try s.phone.cm.reset(identity: s.ids[0]) }

        let names = try s.phone.run { try s.phone.cm.groupNames(containing: s.ids[0], atDepth: 0) }

        #expect(names == ["G"])
    }

    @Test("A fresh exchange with the revoked contact makes the group send again, with no re-adding")
    func reexchangeRestoresTheSend() throws {
        let s = try self.setup()
        try s.phone.run { try s.phone.cm.reset(identity: s.ids[0]) }
        #expect(throws: ContactManager.Errors.groupMembersWithoutKeys([s.ids[0]])) { try self.send(s) }

        let newPhone = try CardPhone()
        try s.phone.run {
            let key = try #require(Contact.Draft.Key(
                material: try newPhone.keyManager.retrieveIdentity(),
                owner: try s.phone.keyManager.retrieveIdentity(),
                date: String(Date().timeIntervalSince1970)
            ))
            try s.phone.cm.update(key: key, for: s.ids[0])
        }

        try self.send(s)
    }
}

// MARK: - The notice's wording

@MainActor
@Suite("GroupRevokedNoticeV3 text")
struct GroupRevokedNoticeTextTests {
    private func text(_ names: [String], all: Bool = false) -> String {
        GroupRevokedNoticeV3.text(names: names, everyoneRevoked: all)
    }

    @Test func one() {
        #expect(self.text(["Alex"]) == "Alex's key is revoked. A message to this group leaves them out until you exchange keys again.")
    }

    @Test func two() {
        #expect(self.text(["Alex", "Jo"]).hasPrefix("Alex and Jo have revoked keys."))
    }

    @Test func three() {
        #expect(self.text(["Alex", "Jo", "Mia"]).hasPrefix("Alex, Jo and 1 other have revoked keys."))
    }

    @Test func four() {
        #expect(self.text(["Alex", "Jo", "Mia", "Sam"]).hasPrefix("Alex, Jo and 2 others have revoked keys."))
    }

    @Test func everyone() {
        #expect(self.text(["Alex", "Jo"], all: true).hasPrefix("No one in this group can receive messages"))
    }
}

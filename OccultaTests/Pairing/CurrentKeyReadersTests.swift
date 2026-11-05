//
//  CurrentKeyReadersTests.swift
//  OccultaTests
//
//  Bug 196: a re-pair leaves a retired key row beside the current one, and a to-many relationship has no order of its own, so
//  "the last row" can be either. Everything that decides revoke, status or the challenge button reads the current row, not the
//  last. These tests put the two rows in both orders.
//

import Testing
import Foundation
import SwiftData
@testable import Occulta

@MainActor
private func makeContactManager() throws -> ContactManager {
    let schema = Schema([
        Group.self, Contact.Profile.self, Contact.Profile.PhoneNumber.self, Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self, Contact.Profile.URLAddress.self, Contact.Profile.Key.self,
    ])
    let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
    return ContactManager(modelContainer: container, security: Manager.Security(modelContainer: container, keyManager: TestKeyManager()))
}

/// A contact with a retired row and a current one, the array in the order given.
@MainActor
private func insertTwicePaired(
    _ cm: ContactManager, retiredFirst: Bool
) throws -> (contact: Contact.Profile, retired: Contact.Profile.Key, current: Contact.Profile.Key) {
    let profile = Contact.Profile(
        identifier: UUID().uuidString, givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    func row(_ byte: UInt8) throws -> Contact.Profile.Key {
        Contact.Profile.Key(
            material: try #require(try Manager.Crypto().encrypt(data: Data(repeating: byte, count: 65))),
            owner: try #require(try Manager.Crypto().encrypt(data: Data(repeating: 9, count: 32))), date: Data(), quantumKeyMaterialEncrypted: nil
        )
    }
    let retired = try row(4), current = try row(5)
    retired.expiredOn = try Manager.Crypto().encrypt(data: Data("1".utf8))
    profile.contactPublicKeys = retiredFirst ? [retired, current] : [current, retired]
    try cm.insertProfile(profile)
    return (profile, retired, current)
}

@MainActor
@Suite("Bug 196 — readers of the current key", .serialized)
struct CurrentKeyReadersTests {

    @Test("Revoke retires the current row, whichever way round the two rows sit", .ambientTestKeyManager, arguments: [true, false])
    func revokeStampsTheCurrentRow(retiredFirst: Bool) throws {
        let cm = try makeContactManager()
        let (contact, retired, current) = try insertTwicePaired(cm, retiredFirst: retiredFirst)
        let retiredStamp = retired.expiredOn

        try cm.reset(identity: contact.identifier)

        #expect(current.expiredOn != nil, "the key in use is the one revoked")
        #expect(contact.currentKey == nil)
        #expect(retired.expiredOn == retiredStamp, "the already-retired row is left alone")
    }

    @Test("Revoking a contact with no current key changes nothing", .ambientTestKeyManager)
    func revokeTwiceChangesNothing() throws {
        let cm = try makeContactManager()
        let (contact, retired, current) = try insertTwicePaired(cm, retiredFirst: true)
        try cm.reset(identity: contact.identifier)
        let stamps = (retired.expiredOn, current.expiredOn)

        try cm.reset(identity: contact.identifier)

        #expect(retired.expiredOn == stamps.0 && current.expiredOn == stamps.1)
    }

    @Test("A twice-paired contact reads as having a usable key in either order: not pending, and the challenge button stays on",
          .ambientTestKeyManager, arguments: [true, false])
    func statusDoesNotDependOnTheOrder(retiredFirst: Bool) throws {
        let cm = try makeContactManager()
        let (contact, _, _) = try insertTwicePaired(cm, retiredFirst: retiredFirst)

        #expect(contact.statusAndCard.status != .pending)
        #expect(contact.displayedKey?.expiredOn == nil, "the row shown is the current one")
    }

    @Test("A fully revoked contact reads as revoked", .ambientTestKeyManager, arguments: [true, false])
    func revokedReadsRevoked(retiredFirst: Bool) throws {
        let cm = try makeContactManager()
        let (contact, _, _) = try insertTwicePaired(cm, retiredFirst: retiredFirst)
        try cm.reset(identity: contact.identifier)

        #expect(contact.displayedKey?.expiredOn != nil)
        #expect(contact.statusAndCard.status == .pending)
    }
}

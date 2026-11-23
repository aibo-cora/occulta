//
//  HybridDowngradeTests.swift
//  OccultaTests
//
//  Bug 199, third part: a re-exchange that would replace a hybrid (ML-KEM) pairing with a classical one is refused, as one
//  that would replace pair keys with none already was. A relay that removes the ML-KEM key from an exchange cannot then
//  downgrade a pairing without the person choosing it: they revoke the contact's key and exchange again.
//
//  Software keys only: `.ambientTestKeyManager` and `SoftwareCardKeys`; no Enclave.
//

import Testing
import Foundation
import SwiftData
@testable import Occulta
@testable import OccultaFormats

@MainActor
private func makeContactManager() throws -> ContactManager {
    let schema = Schema([
        Group.self, Contact.Profile.self, Contact.Profile.PhoneNumber.self, Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self, Contact.Profile.URLAddress.self, Contact.Profile.Key.self,
    ])
    let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
    return ContactManager(
        modelContainer: container, security: Manager.Security(modelContainer: container, keyManager: TestKeyManager()),
        pairKeys: SoftwareCardKeys()
    )
}

@MainActor
private func insert(_ cm: ContactManager, peer: TestKeyManager) throws -> Contact.Profile {
    let profile = Contact.Profile(
        identifier: UUID().uuidString, givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    let row = Contact.Profile.Key(
        material: try Manager.Crypto().encrypt(data: try peer.retrieveIdentity()), owner: Data(), date: Data(),
        quantumKeyMaterialEncrypted: nil
    )
    profile.contactPublicKeys = [row]
    try cm.insertProfile(profile)
    return profile
}

private func quantum() -> QuantumKeyMaterial {
    QuantumKeyMaterial(
        encapsulatedSecret: Data(repeating: 0x31, count: 32), decapsulatedSecret: Data(repeating: 0x32, count: 32),
        ourCiphertext: Data(repeating: 0x41, count: 16), peerCiphertext: Data(repeating: 0x42, count: 16)
    )
}

@MainActor
@Suite("Bug 199 — a hybrid pairing is not replaced by a classical one", .serialized)
struct HybridDowngradeTests {

    private let owner = Data(repeating: 1, count: 65)

    private func key(_ peer: TestKeyManager, hybrid: Bool, date: String = "2") throws -> Contact.Draft.Key {
        try #require(Contact.Draft.Key(
            material: try peer.retrieveIdentity(), owner: self.owner, date: date, quantumKeyMaterial: hybrid ? quantum() : nil
        ))
    }

    /// A contact whose current key holds ML-KEM material, made by a hybrid exchange.
    private func hybridContact(_ cm: ContactManager, peer: TestKeyManager) throws -> Contact.Profile {
        let contact = try insert(cm, peer: peer)
        try cm.update(key: try self.key(peer, hybrid: true), for: contact.identifier)
        try #require(contact.currentKey?.quantumKeyMaterialEncrypted != nil)
        return contact
    }

    @Test("A classical re-exchange over a hybrid pairing is refused and changes nothing", .ambientTestKeyManager)
    func classicalOverHybridIsRefused() throws {
        let cm = try makeContactManager()
        let peer = TestKeyManager()
        let contact = try self.hybridContact(cm, peer: peer)
        try cm.modelContext.save()
        let before = try #require(contact.currentKey)
        let rows = contact.contactPublicKeys?.count
        let quantumBefore = before.quantumKeyMaterialEncrypted

        #expect(throws: ContactManager.Errors.pairingWouldLoseQuantum) {
            try cm.update(key: try self.key(peer, hybrid: false, date: "3"), for: contact.identifier)
        }

        #expect(contact.contactPublicKeys?.count == rows)
        #expect(contact.currentKey === before && before.expiredOn == nil)
        #expect(before.quantumKeyMaterialEncrypted == quantumBefore)
        #expect(!cm.modelContext.hasChanges)
    }

    @Test("A hybrid re-exchange over a hybrid pairing, a hybrid over a classical one and a classical over a classical one are saved", .ambientTestKeyManager)
    func everythingElseIsSaved() throws {
        let cm = try makeContactManager()
        let peer = TestKeyManager()

        let hybrid = try self.hybridContact(cm, peer: peer)
        try cm.update(key: try self.key(peer, hybrid: true, date: "3"), for: hybrid.identifier)
        #expect(hybrid.currentKey?.quantumKeyMaterialEncrypted != nil && hybrid.contactPublicKeys?.count == 3)

        let classical = try insert(cm, peer: peer)
        try cm.update(key: try self.key(peer, hybrid: false), for: classical.identifier)
        #expect(classical.currentKey?.quantumKeyMaterialEncrypted == nil && classical.contactPublicKeys?.count == 2)
        try cm.update(key: try self.key(peer, hybrid: true, date: "3"), for: classical.identifier)
        #expect(classical.currentKey?.quantumKeyMaterialEncrypted != nil)
    }

    @Test("After the contact's key is revoked, a classical exchange is saved: the person chose it", .ambientTestKeyManager)
    func revokeThenClassicalIsSaved() throws {
        let cm = try makeContactManager()
        let peer = TestKeyManager()
        let contact = try self.hybridContact(cm, peer: peer)

        try cm.reset(identity: contact.identifier)
        #expect(contact.currentKey == nil, "revoked")

        try cm.update(key: try self.key(peer, hybrid: false, date: "3"), for: contact.identifier)

        let current = try #require(contact.currentKey)
        #expect(current.quantumKeyMaterialEncrypted == nil)
        #expect(current.expiredOn == nil)
    }

    @Test("The confirmation screen's save reports it as its own outcome, and the screen offers the way on", .ambientTestKeyManager)
    func saveOutcome() throws {
        let cm = try makeContactManager()
        let peer = TestKeyManager()
        let contact = try self.hybridContact(cm, peer: peer)
        let payload = ExchangeManager.ExchangePhase.Payload(
            fingerprint: Data(count: 32), classicalKey: try peer.retrieveIdentity(), hybridResult: nil,
            committed: .init(ourNonce: Data(repeating: 1, count: 16), peerNonce: Data(repeating: 2, count: 16), transcript: Data(repeating: 3, count: 32))
        )

        let outcome = KeyExchange.saveExchange(payload, for: contact.identifier, in: cm, using: TestKeyManager())

        #expect(outcome == .refusedNoQuantum)
        #expect(contact.currentKey?.quantumKeyMaterialEncrypted != nil)

        try cm.reset(identity: contact.identifier)
        #expect(KeyExchange.saveExchange(payload, for: contact.identifier, in: cm, using: TestKeyManager()) == .saved)
    }
}

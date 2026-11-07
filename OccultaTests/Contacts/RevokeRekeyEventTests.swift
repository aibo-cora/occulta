//
//  RevokeRekeyEventTests.swift
//  OccultaTests
//
//  Bug 195 (`Docs/Features/Secure Mode/bugs.md`): `reset(identity:)` expires a contact's last key and leaves no
//  unexpired one, and `update(key:for:)` compared the incoming material with the unexpired key. After a revoke it
//  found nothing to compare with, so `keyRotated` stayed false and `contactKeyRotated` was never sent. Its listener
//  re-sends the depth's backup-key pieces to the trustee's new key (Bug 141), so a revoked trustee kept pieces
//  sealed to a phone they no longer had.
//
//  Runs anywhere: no Enclave.
//

import Testing
import Foundation
import Combine
import CryptoKit
@testable import Occulta

@MainActor
@Suite("Bug 195 — a re-exchange after a revoke reports a changed key", .serialized)
struct RevokeRekeyEventTests {

    /// A contact whose one key is the identity of another phone, and a count of the `contactKeyRotated` events sent.
    private func contact() throws -> (phone: CardPhone, id: String, material: Data, events: EventCount) {
        let phone = try CardPhone(), other = try CardPhone()
        let id = UUID().uuidString
        try phone.addOrdinary(other, as: id)
        return (phone, id, try other.keyManager.retrieveIdentity(), EventCount(phone.cm.contactKeyRotated))
    }

    private func exchange(_ phone: CardPhone, _ material: Data, for id: String) throws {
        try phone.run {
            let key = try #require(Contact.Draft.Key(
                material: material, owner: try phone.keyManager.retrieveIdentity(),
                date: String(Date().timeIntervalSince1970)
            ))
            try phone.cm.update(key: key, for: id)
        }
    }

    private func revoke(_ phone: CardPhone, _ id: String) throws {
        try phone.run { try phone.cm.reset(identity: id) }
    }

    @Test("New material after a revoke sends contactKeyRotated", .ambientTestKeyManager)
    func changedAfterRevokeFires() throws {
        let (phone, id, _, events) = try self.contact()
        try self.revoke(phone, id)

        try self.exchange(phone, newMaterial(), for: id)

        #expect(events.count == 1)
    }

    @Test("The same material after a revoke does not", .ambientTestKeyManager)
    func sameAfterRevokeQuiet() throws {
        let (phone, id, material, events) = try self.contact()
        try self.revoke(phone, id)

        try self.exchange(phone, material, for: id)

        #expect(events.count == 0, "nothing changed: the trustee's pieces still open on that phone")
    }

    @Test("A second exchange of the new material after a revoke does not send it again", .ambientTestKeyManager)
    func repeatedExchangeFiresOnce() throws {
        let (phone, id, _, events) = try self.contact()
        let fresh = newMaterial()
        try self.revoke(phone, id)

        try self.exchange(phone, fresh, for: id)
        try self.exchange(phone, fresh, for: id)

        #expect(events.count == 1)
    }

    @Test("A revoke twice before the re-exchange still sends it once", .ambientTestKeyManager)
    func revokedTwiceFiresOnce() throws {
        let (phone, id, _, events) = try self.contact()
        try self.revoke(phone, id)
        try self.revoke(phone, id)

        try self.exchange(phone, newMaterial(), for: id)

        #expect(events.count == 1)
    }

    @Test("New material with no revoke still sends it", .ambientTestKeyManager)
    func changedWithoutRevokeFires() throws {
        let (phone, id, _, events) = try self.contact()

        try self.exchange(phone, newMaterial(), for: id)

        #expect(events.count == 1)
    }

    @Test("The first key a contact ever has sends nothing", .ambientTestKeyManager)
    func firstKeyQuiet() throws {
        let phone = try CardPhone()
        let id = try phone.newContact("Pat")
        let events = EventCount(phone.cm.contactKeyRotated)

        try self.exchange(phone, newMaterial(), for: id)

        #expect(events.count == 0)
    }

    private func newMaterial() -> Data { P256.KeyAgreement.PrivateKey().publicKey.x963Representation }
}

/// Counts what a subject sends, from construction on.
@MainActor
private final class EventCount {
    private(set) var count = 0
    private var subscription: AnyCancellable?

    init(_ subject: PassthroughSubject<String, Never>) {
        self.subscription = subject.sink { [weak self] _ in self?.count += 1 }
    }
}

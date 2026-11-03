//
//  StaleInboundPrekeysTests.swift
//  OccultaTests
//
//  Bug 194 (`Docs/Features/Secure Mode/bugs.md`): when a contact's identity key changes, what the old phone gave us
//  (its one-time keys, its last-resort key, the batch IDs and the date they were accepted by) must go from our
//  record, or our sends keep sealing to a phone the contact no longer has. Our own batches stay: they don't cause
//  the bug, and dropping them would lose messages the old phone sent before the change.
//
//  Runs anywhere: no Enclave. `StaleInboundPrekeysConversationTests` runs the same events between two phones.
//

import Testing
import Foundation
import CryptoKit
import SwiftData
@testable import Occulta
@testable import OccultaFormats

/// A record with both sides filled: real software prekeys from the contact's old phone, and a batch of ours.
func staleInboundRecord(latest: Date = Date(timeIntervalSince1970: 1_700_000_000)) -> PrekeyRecord {
    func publicKey() -> Data { P256.KeyAgreement.PrivateKey().publicKey.x963Representation }
    var record = PrekeyRecord.empty
    record.ownBatches = [PrekeyRecord.OwnBatch(
        id: randomBytes(16), createdAt: Date(timeIntervalSince1970: 1_700_000_000), retiredAt: nil, isPending: true,
        keys: (0..<3).map { _ in PrekeyRecord.OwnKey(id: randomBytes(16), blob: randomBytes(143), publicKey: nil) }
    )]
    record.inboundBatches = [.init(id: randomBytes(16), keys: (0..<3).map { _ in .init(id: UUID().uuidString, publicKey: publicKey()) })]
    record.inboundLastResort = .init(id: UUID().uuidString, publicKey: publicKey())
    record.acceptedBatchIDs = [randomBytes(16)]
    record.latestInboundGeneratedAt = latest
    return record
}

/// Fresh x963 key material, as a contact's new phone would present it.
func newIdentityMaterial() -> Data {
    P256.KeyAgreement.PrivateKey().publicKey.x963Representation
}

extension CardPhone {
    /// What an exchange stores: `material` as this contact's key, acquired at `acquiredAt`.
    func exchange(_ material: Data, for id: String, at acquiredAt: Date = Date()) throws {
        try self.run {
            let key = try #require(Contact.Draft.Key(
                material: material, owner: try self.keyManager.retrieveIdentity(),
                date: String(acquiredAt.timeIntervalSince1970)
            ))
            try self.cm.update(key: key, for: id)
        }
    }

    /// A key record appended without `update(key:for:)`, as the app stored one before Bug 194's fix.
    func appendKeyRecord(_ material: Data, for id: String, acquiredAt: Date, expired: Bool = false) throws {
        try self.run {
            let crypto = Manager.Crypto()
            let key = Contact.Profile.Key(
                material: try #require(try crypto.encrypt(data: material)),
                owner: Data(),
                date: try #require(try crypto.encrypt(data: Data(String(acquiredAt.timeIntervalSince1970).utf8))),
                quantumKeyMaterialEncrypted: nil
            )
            if expired { key.expiredOn = try crypto.encrypt(data: Data("1".utf8)) }
            try self.contact(id).contactPublicKeys?.append(key)
            try self.cm.modelContext.save()
        }
    }

    func nextSend(to id: String) throws -> NextSendSecrecy {
        try self.run { self.cm.nextSendSecrecy(for: try self.contact(id)) }
    }
}

/// `record` as the contact's old phone left it, with the inbound side gone.
private func inboundDropped(_ record: PrekeyRecord) -> PrekeyRecord {
    var expected = record
    expected.inboundBatches = []
    expected.inboundLastResort = nil
    expected.acceptedBatchIDs = []
    expected.latestInboundGeneratedAt = nil
    return expected
}

@MainActor
@Suite("Bug 194 — a contact's key change drops their prekeys from our record", .serialized)
struct StaleInboundPrekeysTests {

    /// A contact whose one key is `other`'s identity, with `record` stored.
    private func stuck(_ record: PrekeyRecord = staleInboundRecord()) throws -> (phone: CardPhone, id: String, material: Data, record: PrekeyRecord) {
        let phone = try CardPhone(), other = try CardPhone()
        let id = UUID().uuidString
        try phone.addOrdinary(other, as: id)
        try phone.store(record, for: id)
        return (phone, id, try other.keyManager.retrieveIdentity(), record)
    }

    // MARK: - update(key:for:)

    @Test("New material empties the inbound side and leaves our own batches", .ambientTestKeyManager)
    func newMaterialDropsInbound() throws {
        let (phone, id, _, record) = try self.stuck()

        try phone.exchange(newIdentityMaterial(), for: id)

        let after = try phone.record(id)
        #expect(after.inboundBatches.isEmpty)
        #expect(after.inboundLastResort == nil)
        #expect(after.acceptedBatchIDs.isEmpty)
        #expect(after.latestInboundGeneratedAt == nil)
        #expect(after == inboundDropped(record), "only the inbound side goes: own batches and legacy keys stay")
    }

    @Test("The same material keeps the record, as a reinstall does (Bug 82)", .ambientTestKeyManager)
    func sameMaterialKeeps() throws {
        let (phone, id, material, record) = try self.stuck()

        try phone.exchange(material, for: id)

        #expect(try phone.record(id) == record)
    }

    @Test("The first key a contact ever has leaves the record alone", .ambientTestKeyManager)
    func firstKeyKeeps() throws {
        let phone = try CardPhone()
        let id = try phone.newContact("Pat")
        let record = staleInboundRecord()
        try phone.store(record, for: id)

        try phone.exchange(newIdentityMaterial(), for: id)

        #expect(try phone.record(id) == record)
    }

    @Test("The first send after a key change is long-term, not on a stale prekey", .ambientTestKeyManager)
    func firstSendIsLongTerm() throws {
        let (phone, id, _, _) = try self.stuck()
        #expect(try phone.nextSend(to: id) == .forwardSecret, "precondition: the stale keys are what we'd seal to")

        try phone.exchange(newIdentityMaterial(), for: id)

        #expect(try phone.nextSend(to: id) == .longTerm)
    }

    @Test("A last-resort key alone is dropped too", .ambientTestKeyManager)
    func lastResortAloneIsDropped() throws {
        var record = staleInboundRecord()
        record.inboundBatches = []
        let (phone, id, _, _) = try self.stuck(record)
        #expect(try phone.nextSend(to: id) == .temporaryKey, "precondition")

        try phone.exchange(newIdentityMaterial(), for: id)

        #expect(try phone.record(id).inboundLastResort == nil)
        #expect(try phone.nextSend(to: id) == .longTerm)
    }

    // MARK: - reset(identity:)

    @Test("Revoking a contact's key empties the inbound side and leaves our own batches", .ambientTestKeyManager)
    func resetDropsInbound() throws {
        let (phone, id, _, record) = try self.stuck()

        try phone.run { try phone.cm.reset(identity: id) }

        #expect(try phone.record(id) == inboundDropped(record))
        #expect(try phone.run { try phone.contact(id).contactPublicKeys?.last?.expiredOn } != nil, "the key is still revoked")
    }

    /// The next exchange compares against the unexpired key, and a revoked contact has none, so it can't be relied
    /// on to see the change: `reset` has to drop the state itself.
    @Test("After a revoke, a re-exchange with a new key finds nothing stale", .ambientTestKeyManager)
    func revokeThenReexchange() throws {
        let (phone, id, _, record) = try self.stuck()

        try phone.run { try phone.cm.reset(identity: id) }
        try phone.exchange(newIdentityMaterial(), for: id)

        #expect(try phone.record(id) == inboundDropped(record))
        #expect(try phone.nextSend(to: id) == .longTerm)
    }

    @Test("Revoking a contact with an empty record changes nothing", .ambientTestKeyManager)
    func resetOnEmptyRecord() throws {
        let (phone, id, _, _) = try self.stuck(.empty)

        try phone.run { try phone.cm.reset(identity: id) }

        #expect(try phone.record(id) == .empty)
    }
}

@MainActor
@Suite("Bug 194 — the launch pass for contacts already stuck", .serialized)
struct StaleInboundPrekeysLaunchPassTests {

    private let t0 = Date(timeIntervalSince1970: 1_700_000_000)

    private func contact(keys: [(String, Double, Bool)], record: PrekeyRecord) throws -> (CardPhone, String) {
        let phone = try CardPhone()
        let id = try phone.newContact("Pat")
        var materials: [String: Data] = [:]
        for (name, offset, expired) in keys {
            let material = materials[name] ?? newIdentityMaterial()
            materials[name] = material
            try phone.appendKeyRecord(material, for: id, acquiredAt: self.t0.addingTimeInterval(offset), expired: expired)
        }
        try phone.store(record, for: id)
        return (phone, id)
    }

    private func sweep(_ phone: CardPhone) throws {
        try phone.run { try phone.cm.sweepStaleInboundPrekeys() }
    }

    @Test("Their batch is older than the current key: the inbound side goes, ours stays", .ambientTestKeyManager)
    func staleIsDropped() throws {
        let record = staleInboundRecord(latest: self.t0)
        let (phone, id) = try self.contact(keys: [("A", 0, false), ("B", 100, false)], record: record)

        try self.sweep(phone)

        #expect(try phone.record(id) == inboundDropped(record))
    }

    @Test("Their batch is newer than the current key: the new phone issued it, so it stays", .ambientTestKeyManager)
    func freshIsKept() throws {
        let record = staleInboundRecord(latest: self.t0.addingTimeInterval(200))
        let (phone, id) = try self.contact(keys: [("A", 0, false), ("B", 100, false)], record: record)

        try self.sweep(phone)

        #expect(try phone.record(id) == record)
    }

    @Test("A contact with one key is left alone", .ambientTestKeyManager)
    func oneKeyIsKept() throws {
        let record = staleInboundRecord(latest: self.t0)
        let (phone, id) = try self.contact(keys: [("A", 100, false)], record: record)

        try self.sweep(phone)

        #expect(try phone.record(id) == record)
    }

    @Test("The same material twice is a reinstall, not a change", .ambientTestKeyManager)
    func sameMaterialIsKept() throws {
        let record = staleInboundRecord(latest: self.t0)
        let (phone, id) = try self.contact(keys: [("A", 0, false), ("A", 100, false)], record: record)

        try self.sweep(phone)

        #expect(try phone.record(id) == record)
    }

    @Test("A second exchange with the new key doesn't hide the change", .ambientTestKeyManager)
    func repeatedNewKeyIsDropped() throws {
        let record = staleInboundRecord(latest: self.t0)
        let (phone, id) = try self.contact(keys: [("A", 0, false), ("B", 100, false), ("B", 300, false)], record: record)

        try self.sweep(phone)

        #expect(try phone.record(id) == inboundDropped(record), "judged against when the current key first appeared, at 100")
    }

    @Test("A contact revoked and re-exchanged before the fix is repaired", .ambientTestKeyManager)
    func revokedBeforeTheFix() throws {
        let record = staleInboundRecord(latest: self.t0)
        let (phone, id) = try self.contact(keys: [("A", 0, true), ("B", 100, false)], record: record)

        try self.sweep(phone)

        #expect(try phone.record(id) == inboundDropped(record))
        #expect(try phone.nextSend(to: id) == .longTerm)
    }

    @Test("A second run finds nothing to do", .ambientTestKeyManager)
    func idempotent() throws {
        let (phone, id) = try self.contact(keys: [("A", 0, false), ("B", 100, false)], record: staleInboundRecord(latest: self.t0))

        try self.sweep(phone)
        let once = try phone.record(id)
        try self.sweep(phone)

        #expect(try phone.record(id) == once)
    }

    @Test("A record with nothing inbound is left alone", .ambientTestKeyManager)
    func emptyInboundIsKept() throws {
        var record = staleInboundRecord(latest: self.t0)
        record = inboundDropped(record)
        let (phone, id) = try self.contact(keys: [("A", 0, false), ("B", 100, false)], record: record)

        try self.sweep(phone)

        #expect(try phone.record(id) == record)
    }

    @Test("A key whose date won't read leaves the record alone", .ambientTestKeyManager)
    func unreadableDateIsKept() throws {
        let record = staleInboundRecord(latest: self.t0)
        let phone = try CardPhone(), other = try CardPhone()
        let id = UUID().uuidString
        try phone.addOrdinary(other, as: id)
        try phone.exchange(newIdentityMaterial(), for: id, at: self.t0.addingTimeInterval(100))
        try phone.store(record, for: id)
        try phone.run {
            try phone.contact(id).contactPublicKeys?.last?.acquiredAt = Data()
            try phone.cm.modelContext.save()
        }

        try self.sweep(phone)

        #expect(try phone.record(id) == record)
    }
}

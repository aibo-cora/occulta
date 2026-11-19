//
//  PrekeyValidityTests.swift
//  OccultaTests
//
//  Bug 204: a contact's prekey batch was accepted on its sizes alone, so a key that is not a point on the curve stopped
//  every send to them (and to any group they are in) with `keyDerivationFailed`. A batch is now accepted only if every key
//  loads, and a send drops a stored key that doesn't and goes on to the next.
//
//  Bug 205: a send that failed after taking a one-time key of the contact's still used the key up.
//

import Testing
import Foundation
import CryptoKit
import SwiftData
@testable import Occulta
@testable import OccultaCore
@testable import OccultaFormats

private func badKey() -> Data { Data(repeating: 0x04, count: 65) }

private func inbound(_ key: Data) -> PrekeyRecord.InboundKey {
    PrekeyRecord.InboundKey(id: UUID().uuidString, publicKey: key)
}

@Suite("Bug 204 — the bookkeeper holds prekeys to being curve points")
struct PrekeyPointTests {

    let bookkeeper = PrekeyBookkeeper()

    private func accept(_ prekeys: [Data], lastResort: Data? = nil, into record: inout PrekeyRecord) throws -> Bool {
        try self.bookkeeper.accept(
            id: randomBytes(16), generatedAt: Date(),
            prekeys: prekeys.map { OccultaBundle.WirePrekey(id: UUID().uuidString, publicKey: $0) },
            lastResort: lastResort.map { OccultaBundle.WirePrekey(id: UUID().uuidString, publicKey: $0) },
            onReopenableSlot: false, into: &record
        )
    }

    @Test("A batch with a 65-byte key that is not a point is rejected and changes nothing")
    func nonPointRejected() {
        var record = PrekeyRecord.empty
        #expect(throws: PrekeyBookkeeper.BookkeeperError.malformedBatch) {
            try self.accept([randomPoint(), badKey(), randomPoint()], into: &record)
        }
        #expect(record == .empty)
    }

    @Test("A last-resort key that is not a point makes the batch malformed")
    func nonPointLastResortRejected() {
        var record = PrekeyRecord.empty
        #expect(throws: PrekeyBookkeeper.BookkeeperError.malformedBatch) {
            try self.accept([randomPoint()], lastResort: badKey(), into: &record)
        }
        #expect(record == .empty)
    }

    @Test("A batch of real points is still accepted")
    func realPointsAccepted() throws {
        var record = PrekeyRecord.empty
        #expect(try self.accept([randomPoint(), randomPoint()], lastResort: randomPoint(), into: &record))
    }

    @Test("A stored key that is not a point is dropped, and the next one is taken")
    func takeSkipsNonPoints() throws {
        let good = inbound(randomPoint())
        var record = PrekeyRecord.empty
        record.inboundBatches = [PrekeyRecord.InboundBatch(id: nil, keys: [inbound(badKey()), inbound(badKey()), good, inbound(randomPoint())])]

        let taken = try #require(self.bookkeeper.takeInboundPrekey(from: &record, contactID: "c"))

        #expect(taken.id == good.id)
        #expect(record.inboundBatches.first?.keys.count == 1, "the two bad keys and the one taken are gone")
    }

    @Test("With only non-points stored, nothing is taken and none is left")
    func takeFindsNoneWhenAllAreBad() {
        var record = PrekeyRecord.empty
        record.inboundBatches = [PrekeyRecord.InboundBatch(id: nil, keys: [inbound(badKey()), inbound(badKey())])]

        #expect(self.bookkeeper.takeInboundPrekey(from: &record, contactID: "c") == nil)
        #expect(record.inboundBatches.isEmpty)
    }

    @Test("A last-resort key that is not a point is not offered")
    func lastResortNonPointNotOffered() {
        var record = PrekeyRecord.empty
        record.inboundLastResort = inbound(badKey())
        #expect(self.bookkeeper.lastResortPrekey(in: record, contactID: "c") == nil)

        record.inboundLastResort = inbound(randomPoint())
        #expect(self.bookkeeper.lastResortPrekey(in: record, contactID: "c") != nil)
    }
}

// MARK: - A send

@Suite("Bugs 204 and 205 — a send with bad or failing prekeys", .serialized)
@MainActor
struct PrekeySendTests {

    private func fixture(inbound keys: [PrekeyRecord.InboundKey], lastResort: PrekeyRecord.InboundKey? = nil) throws -> (ContactManager, Contact.Profile) {
        let cm = try TestSupport.makeContactManager()
        try insertStreamedSender(identifier: "bob", publicKey: try TestKeyManager().retrieveIdentity(), in: cm)
        let bob = try #require(try cm.fetchContact(by: "bob"))

        var record = try cm.prekeyRecord(for: bob)
        record.inboundBatches = keys.isEmpty ? [] : [PrekeyRecord.InboundBatch(id: nil, keys: keys)]
        record.inboundLastResort = lastResort
        try cm.store(record, for: bob)
        try cm.modelContext.save()
        return (cm, bob)
    }

    /// A destination whose directory doesn't exist: the bundle is sealed, and writing it fails.
    private func failingOutput() -> BundleOutput {
        .file(
            destination: FileManager.default.temporaryDirectory
                .appendingPathComponent("missing-\(UUID().uuidString)").appendingPathComponent("out.occ"),
            attachments: nil, memoryGuard: .system
        )
    }

    // MARK: Bug 204

    @Test("A send to a contact holding a bad key and a good one produces a bundle, and uses the good one", .ambientTestKeyManager)
    func sendSkipsBadKey() throws {
        let (cm, bob) = try self.fixture(inbound: [inbound(badKey()), inbound(randomPoint())])

        let bundle = try cm.encryptBundle(basket: Basket(files: []), for: "bob")

        #expect(!bundle.isEmpty)
        #expect(try cm.prekeyRecord(for: bob).inboundBatches.isEmpty, "the bad key was dropped and the good one used")
    }

    @Test("A send to a contact holding only bad keys falls back to the long-term mode", .ambientTestKeyManager)
    func sendWithOnlyBadKeys() throws {
        let (cm, bob) = try self.fixture(inbound: [inbound(badKey()), inbound(badKey())], lastResort: inbound(badKey()))

        let bundle = try cm.encryptBundle(basket: Basket(files: []), for: "bob")

        #expect(!bundle.isEmpty)
        #expect(try cm.prekeyRecord(for: bob).inboundBatches.isEmpty, "the keys that can't be used are not kept")
    }

    @Test("A group send to a member holding a bad key produces a bundle", .ambientTestKeyManager)
    func groupSendSkipsBadKey() throws {
        let (cm, _) = try self.fixture(inbound: [inbound(badKey()), inbound(randomPoint())], lastResort: inbound(badKey()))
        let group = try cm.createGroup(name: "G")
        try group.addMember("bob", atDepth: 0)

        let bundle = try cm.encryptGroupBundle(basket: Basket(files: []), groupID: try #require(group.readID()))

        #expect(!bundle.isEmpty)
    }

    // MARK: Bug 205

    @Test("A one-to-one send that throws after taking a key leaves the contact's record as it was", .ambientTestKeyManager)
    func failedSendKeepsTheKey() throws {
        let (cm, bob) = try self.fixture(inbound: [inbound(randomPoint()), inbound(randomPoint())])
        let before = bob.prekeyRecordEncrypted

        #expect(throws: (any Error).self) {
            try cm.encryptBundle(basket: Basket(files: []), for: "bob", output: self.failingOutput())
        }

        #expect(bob.prekeyRecordEncrypted == before, "the shortened record must not stay on the contact")
        try cm.modelContext.save()
        let fresh = try #require(try cm.fetchContact(by: "bob"))
        #expect(try cm.prekeyRecord(for: fresh).inboundBatches.first?.keys.count == 2, "and a later save must not commit it")
    }

    @Test("A group send that throws after taking a key leaves every member's record as it was", .ambientTestKeyManager)
    func failedGroupSendKeepsTheKeys() throws {
        let (cm, bob) = try self.fixture(inbound: [inbound(randomPoint()), inbound(randomPoint())])
        let group = try cm.createGroup(name: "G")
        try group.addMember("bob", atDepth: 0)
        let before = bob.prekeyRecordEncrypted

        #expect(throws: (any Error).self) {
            try cm.encryptGroupBundle(basket: Basket(files: []), groupID: try #require(group.readID()), output: self.failingOutput())
        }

        #expect(bob.prekeyRecordEncrypted == before)
        try cm.modelContext.save()
        let fresh = try #require(try cm.fetchContact(by: "bob"))
        #expect(try cm.prekeyRecord(for: fresh).inboundBatches.first?.keys.count == 2)
    }

    @Test("A send that succeeds still uses the key up", .ambientTestKeyManager)
    func successfulSendConsumesTheKey() throws {
        let (cm, bob) = try self.fixture(inbound: [inbound(randomPoint()), inbound(randomPoint())])

        _ = try cm.encryptBundle(basket: Basket(files: []), for: "bob")

        #expect(try cm.prekeyRecord(for: bob).inboundBatches.first?.keys.count == 1)
    }
}

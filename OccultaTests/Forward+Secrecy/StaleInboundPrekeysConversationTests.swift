//
//  StaleInboundPrekeysConversationTests.swift
//  OccultaTests
//
//  ⚠️  Requires a Secure Enclave: prekeys are Enclave blobs, generated as each phone's refills come due.
//
//  Bug 194, end to end (`Docs/Features/Secure Mode/bugs.md`): Alice and Bob talk until she holds his prekeys, then
//  Bob gets a new phone and Alice stores its key. Her next message must open on the new phone and not on the old
//  one. Phones are `CardPhone`s, each with its own identity and store, exchanging real bundles through
//  `encryptBundle` and `openGroup`. Neither has ML-KEM material for the other, so the messages go in
//  `.forwardSecretNoPQ`, the mode the old phone could read before the fix.
//
//  `StaleInboundPrekeysTests` covers the record rules without an Enclave.
//

import Testing
import Foundation
@testable import Occulta
@testable import OccultaFormats

@MainActor
@Suite("Bug 194 — a contact's new phone, end to end", .enabled(if: TestSupport.secureEnclaveAvailable()), .serialized)
struct StaleInboundPrekeysConversationTests {

    /// Alice and Bob have talked: she holds his one-time keys and his last-resort key, and he holds hers.
    @MainActor
    private struct Talked {
        let alice: CardPhone
        let oldBob: CardPhone
        let bobSide = "bob"
        let aliceSide = "alice"

        init() throws {
            self.alice = try CardPhone()
            self.oldBob = try CardPhone()
            try self.alice.addOrdinary(self.oldBob, as: self.bobSide)
            try self.oldBob.addOrdinary(self.alice, as: self.aliceSide)

            try self.oldBob.receive(try self.alice.send(to: self.bobSide))
            try self.alice.receive(try self.oldBob.send(to: self.aliceSide))
            #expect(try self.alice.nextSend(to: self.bobSide) == .forwardSecret, "precondition: Alice holds Bob's keys")
            #expect(try self.alice.record(self.bobSide).inboundLastResort != nil, "precondition: and his last-resort key")
        }

        /// Bob's new phone, which knows Alice from an in-person exchange and nothing of the old phone's keys.
        func newBob() throws -> CardPhone {
            let phone = try CardPhone()
            try phone.addOrdinary(self.alice, as: self.aliceSide)
            return phone
        }

        func aliceStoresKey(of phone: CardPhone) throws {
            try self.alice.exchange(try phone.keyManager.retrieveIdentity(), for: self.bobSide)
        }
    }

    @Test("After the key change, what Alice sends opens on the new phone and not on the old one")
    func newPhoneOpens() throws {
        let talked = try Talked()
        let newBob = try talked.newBob()
        try talked.aliceStoresKey(of: newBob)

        let message = try talked.alice.send(to: talked.bobSide, "after")

        #expect(try newBob.receive(message).text == "after")
        #expect(throws: (any Error).self, "the old phone's keys no longer open it") { try talked.oldBob.receive(message) }
    }

    @Test("The new phone answers with a batch, and forward secrecy resumes")
    func conversationRecovers() throws {
        let talked = try Talked()
        let newBob = try talked.newBob()
        try talked.aliceStoresKey(of: newBob)

        try newBob.receive(try talked.alice.send(to: talked.bobSide))
        try talked.alice.receive(try newBob.send(to: talked.aliceSide))

        #expect(try talked.alice.nextSend(to: talked.bobSide) == .forwardSecret)
        #expect(try newBob.receive(try talked.alice.send(to: talked.bobSide, "again")).text == "again")
    }

    @Test("A revoke and then a re-exchange gives the same result")
    func revokeThenReexchange() throws {
        let talked = try Talked()
        try talked.alice.run { try talked.alice.cm.reset(identity: talked.bobSide) }
        let newBob = try talked.newBob()
        try talked.aliceStoresKey(of: newBob)

        let message = try talked.alice.send(to: talked.bobSide, "after revoke")

        #expect(try newBob.receive(message).text == "after revoke")
        #expect(throws: (any Error).self) { try talked.oldBob.receive(message) }
    }

    @Test("A contact stuck before the fix is repaired by the launch pass")
    func launchPassRepairs() throws {
        let talked = try Talked()
        let newBob = try talked.newBob()
        // The key stored as the app did before the fix: appended, with the old phone's prekeys left in the record.
        try talked.alice.appendKeyRecord(
            try newBob.keyManager.retrieveIdentity(), for: talked.bobSide, acquiredAt: Date().addingTimeInterval(60)
        )
        #expect(try talked.alice.nextSend(to: talked.bobSide) == .forwardSecret, "precondition: stuck")
        #expect(throws: (any Error).self, "precondition: the new phone can't open what she sends") {
            try newBob.receive(try talked.alice.send(to: talked.bobSide))
        }

        try talked.alice.run { try talked.alice.cm.sweepStaleInboundPrekeys() }

        let message = try talked.alice.send(to: talked.bobSide, "repaired")
        #expect(try newBob.receive(message).text == "repaired")
    }
}

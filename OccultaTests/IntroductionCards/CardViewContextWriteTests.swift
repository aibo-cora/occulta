//
//  CardViewContextWriteTests.swift
//  OccultaTests
//
//  A card screen holds its contact through `@Query`, in the container's main context, while `ContactManager` works in
//  its own. The card methods used to take that row and write it, then save the manager's context, which held no change:
//  the write reached the store only at SwiftData's autosave. Importing a card into an existing contact then failed the
//  first Encrypt with `contactHasNoKeys` (compose read the field through the manager as `.empty`), and the checkpoint
//  after a cancel or a discard ran before the write landed. They take the contact's identifier now; these check that
//  each write is in the store as it returns, while a view holds the same contact.
//

import Testing
import Foundation
import SwiftData
import OccultaCore
@testable import Occulta
@testable import OccultaFormats

@MainActor
@Suite("Card writes reach the store while a view holds the contact", .serialized, .enabled(if: TestSupport.secureEnclaveAvailable()))
struct CardViewContextWriteTests {

    /// The contact as a view's `@Query` holds it: in the main context, not the manager's.
    private func viewRow(_ phone: CardPhone, _ id: String) throws -> Contact.Profile {
        try #require(try phone.container.mainContext.fetch(
            FetchDescriptor<Contact.Profile>(predicate: #Predicate { $0.identifier == id })
        ).first)
    }

    /// The contact as the store has it, through a context nothing else has touched.
    private func stored(_ phone: CardPhone, _ id: String) throws -> Contact.Profile {
        let fresh = ModelContext(phone.container)
        return try #require(try fresh.fetch(FetchDescriptor<Contact.Profile>(predicate: #Predicate { $0.identifier == id })).first)
    }

    @Test("Import into an existing contact: in the store, and the first send works")
    func importIntoExistingContact() throws {
        let bob = try CardPhone(), carol = try CardPhone()
        let bobSide = try bob.newContact("Carol"), carolSide = try carol.newContact("Bob")
        let card = try bob.run { try bob.cm.createCard(for: bobSide) }
        _ = try self.viewRow(carol, carolSide)

        let outcome = try carol.run { try carol.cm.importCard(card.encoded, into: carolSide, newContactName: nil) }

        #expect(outcome == .imported(contactIdentifier: carolSide))
        #expect(try carol.run { try self.stored(carol, carolSide).cardState.isCardContact })
        #expect(!carol.container.mainContext.hasChanges, "nothing waits on the view's context")
        _ = try carol.send(to: carolSide, "first")
    }

    @Test("Create: the issued card is in the store")
    func create() throws {
        let bob = try CardPhone()
        let bobSide = try bob.newContact("Carol")
        _ = try self.viewRow(bob, bobSide)

        _ = try bob.run { try bob.cm.createCard(for: bobSide) }

        guard case .issued = try bob.run({ try self.stored(bob, bobSide).cardState }) else {
            Issue.record("the issued card is not in the store")
            return
        }
        #expect(!bob.container.mainContext.hasChanges)
    }

    @Test("Cancel: the store holds the empty state")
    func cancel() throws {
        let bob = try CardPhone()
        let bobSide = try bob.newContact("Carol")
        _ = try bob.run { try bob.cm.createCard(for: bobSide) }
        _ = try self.viewRow(bob, bobSide)

        try bob.run { try bob.cm.cancelCard(for: bobSide) }

        #expect(try bob.run { try self.stored(bob, bobSide).cardState } == .empty)
        #expect(!bob.container.mainContext.hasChanges)
    }

    @Test("Discard: the store holds the empty state and no card-era batches")
    func discard() throws {
        let pair = try CardPhonePair()
        try pair.converse()
        _ = try self.viewRow(pair.bob, pair.bobSide)

        try pair.bob.run { try pair.bob.cm.discardCardConversation(for: pair.bobSide) }

        let record = try pair.bob.run { try pair.bob.cm.prekeyRecord(for: try self.stored(pair.bob, pair.bobSide)) }
        #expect(try pair.bob.run { try self.stored(pair.bob, pair.bobSide).cardState } == .empty)
        #expect(record.inboundBatches.isEmpty && record.ownBatches.isEmpty && record.acceptedBatchIDs.isEmpty)
        #expect(!pair.bob.container.mainContext.hasChanges)
    }

    @Test("An identifier no contact has: refused, nothing created")
    func unknownIdentifier() throws {
        let bob = try CardPhone(), carol = try CardPhone()
        let bobSide = try bob.newContact("Carol")
        let card = try bob.run { try bob.cm.createCard(for: bobSide) }
        let before = try carol.run { try carol.cm.fetchAllContacts().count }

        #expect(throws: ContactManager.Errors.contactNotFound) {
            try carol.run { try carol.cm.importCard(card.encoded, into: "no such contact", newContactName: nil) }
        }
        #expect(throws: ContactManager.Errors.contactNotFound) { try bob.run { try bob.cm.createCard(for: "no such contact") } }
        #expect(try carol.run { try carol.cm.fetchAllContacts().count } == before)
    }
}

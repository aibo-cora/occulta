//
//  CardIssueImportTests.swift
//  OccultaTests
//
//  Introduction cards, stage B (`Docs/Features/Introduction Cards/SPEC.md` §6.1 to §6.4): Bob creates, cancels and
//  shares a card; Carol imports it; the unlock sweep clears dead ones. Two phones are two `ContactManager`s on
//  separate in-memory stores. Their card keys are software P-256 keys whose blob is the raw private key, and their
//  ML-KEM key is `PostQuantumProviderFactory.createForTesting()`'s, so nothing here needs an Enclave except the
//  tests that import successfully: those make Carol's pending prekey batch through `PrekeySecretsManager`, whose
//  private keys live in the Enclave, and carry `.enabled(if:)`. Everything else runs under `.ambientTestKeyManager`.
//
//  The last suite is E1/E2: what the card makes of `verificationStatus`, and the hard blocks on groups and the
//  vault trustee list. The screens' own loops are private to their views, so those tests check the predicates the
//  views call, on real stored states.
//

import Testing
import Foundation
import CryptoKit
import SwiftData
import OccultaCore
@testable import Occulta
@testable import OccultaFormats

// MARK: - Software card keys

/// `CardKeyProviding` with CryptoKit software keys: the blob is the key's raw representation. `failing` makes the
/// next key generation throw, to test that a failure leaves the field as it was.
nonisolated final class SoftwareCardKeys: CardKeyProviding, @unchecked Sendable {

    enum Failure: Error { case injected }

    var failing = false

    func makeAgreementKey() throws -> (publicKey: Data, blob: Data) {
        if self.failing { throw Failure.injected }
        let key = P256.KeyAgreement.PrivateKey()
        return (key.publicKey.x963Representation, key.rawRepresentation)
    }

    func makeSigningKey() throws -> (publicKey: Data, blob: Data) {
        if self.failing { throw Failure.injected }
        let key = P256.Signing.PrivateKey()
        return (key.publicKey.x963Representation, key.rawRepresentation)
    }

    func signRaw(_ payload: Data, signingBlob: Data) throws -> Data {
        try P256.Signing.PrivateKey(rawRepresentation: signingBlob).signature(for: payload).rawRepresentation
    }

    func signDER(_ payload: Data, signingBlob: Data) throws -> Data {
        try P256.Signing.PrivateKey(rawRepresentation: signingBlob).signature(for: payload).derRepresentation
    }

    func sharedSecret(agreementBlob: Data, peerPublicKey: Data) throws -> Data {
        let key  = try P256.KeyAgreement.PrivateKey(rawRepresentation: agreementBlob)
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: peerPublicKey)
        return try key.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Data($0) }
    }

    func agreementPublicKey(blob: Data) throws -> Data {
        try P256.KeyAgreement.PrivateKey(rawRepresentation: blob).publicKey.x963Representation
    }

    func signingPublicKey(blob: Data) throws -> Data {
        try P256.Signing.PrivateKey(rawRepresentation: blob).publicKey.x963Representation
    }
}

// MARK: - Helpers

private let t0 = Date(timeIntervalSince1970: 1_800_000_000)
private let hour: TimeInterval = 3_600
private let day: TimeInterval = 24 * hour

/// One phone: its own store, software card keys and in-memory ML-KEM.
@MainActor
private struct Phone {
    let cm: ContactManager
    let container: ModelContainer
    let keys: SoftwareCardKeys
    let pq: any PostQuantumProvider

    init(withPostQuantum: Bool = true) throws {
        let schema = Schema([
            Group.self,
            Contact.Profile.self,
            Contact.Profile.PhoneNumber.self,
            Contact.Profile.EmailAddress.self,
            Contact.Profile.PostalAddress.self,
            Contact.Profile.URLAddress.self,
            Contact.Profile.Key.self,
        ])
        let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
        let security  = try Manager.Security(modelContainer: container, keyManager: TestKeyManager())
        let pq        = try #require(PostQuantumProviderFactory.createForTesting())
        let keys      = SoftwareCardKeys()
        self.container = container
        self.keys = keys
        self.pq   = pq
        self.cm   = ContactManager(modelContainer: container, security: security, cardKeys: keys, cardPostQuantum: withPostQuantum ? pq : nil)
    }

    /// A new pending contact, found again by comparing identifiers, since the stored one is sealed.
    func contact(_ name: String = "Pat", depth: Int = 0) throws -> Contact.Profile {
        let before = Set(try self.cm.fetchAllContacts().map(\.identifier))
        try self.cm.save(contact: Contact.Draft(identifier: UUID().uuidString, givenName: name, familyName: ""), currentDepth: depth)
        return try #require(try self.cm.fetchAllContacts().first { !before.contains($0.identifier) })
    }
}

private func inPersonKey() throws -> Contact.Profile.Key {
    let ours = try Manager.Ambient.keyManager.retrieveIdentity().sha256
    return Contact.Profile.Key(
        material: try Data(count: 65).encrypt(),
        owner: try #require(try ours.encrypt()),
        date: try #require(try Data("0".utf8).encrypt())
    )
}

private func issuedCard(_ state: CardState) -> Data? {
    if case .issued(let card, _, _, _, _) = state { return card }
    return nil
}

private func importedState(expiresAt: Date, sent: Bool) -> CardState {
    .imported(
        peerCard: randomBytes(1_770), agreementKey: randomBytes(143), signingKey: randomBytes(143),
        mlkemKey: randomBytes(4_788), ss1: randomBytes(32), ct1: randomBytes(1_568),
        expiresAt: expiresAt, sentFirstMessage: sent
    )
}

private func issuedState(expiresAt: Date) -> CardState {
    .issued(card: randomBytes(1_770), agreementKey: randomBytes(143), signingKey: randomBytes(143),
            mlkemKey: randomBytes(4_788), expiresAt: expiresAt)
}

private func conversationState() -> CardState {
    .conversation(
        agreementKey: randomBytes(143), signingKey: randomBytes(143),
        peerAgreementKey: randomBytes(65), peerSigningKey: randomBytes(65),
        mlkemKey: randomBytes(4_788), quantum: nil, bootstrapOpen: true, peerIntroduction: nil
    )
}

private func pendingBatch() -> PrekeyRecord.OwnBatch {
    PrekeyRecord.OwnBatch(
        id: randomBytes(16), createdAt: t0, retiredAt: nil, isPending: true,
        keys: (0..<3).map { _ in PrekeyRecord.OwnKey(id: randomBytes(16), blob: randomBytes(143), publicKey: nil) }
    )
}

private func deliveredBatch() -> PrekeyRecord.OwnBatch {
    PrekeyRecord.OwnBatch(
        id: nil, createdAt: t0, retiredAt: nil, isPending: false,
        keys: (0..<3).map { _ in PrekeyRecord.OwnKey(id: randomBytes(16), blob: randomBytes(143), publicKey: nil) }
    )
}

/// Whether the import tests can run: they generate Carol's prekey batch in the Enclave.
private let enclave = TestSupport.secureEnclaveAvailable()

// MARK: - Create, cancel, share

@MainActor
@Suite("Card — create, cancel and share (SPEC §6.1, §6.2, §2)", .serialized)
struct CardCreateTests {

    @Test("A created card is stored as issued, recognises, and its keys are the provider's", .ambientTestKeyManager)
    func storedIssued() throws {
        let bob = try Phone()
        let contact = try bob.contact()

        let card = try bob.cm.createCard(for: contact, now: t0)

        guard case .issued(let stored, let agreementBlob, let signingBlob, let mlkemBlob, let expiresAt) = contact.cardState else {
            Issue.record("the field should hold an issued card")
            return
        }
        #expect(stored == card.encoded)
        #expect(IntroductionCard.recognize(stored) == card, "what Bob hands out is what Carol recognises")
        #expect(expiresAt == card.expiresAt)
        #expect(try P256.KeyAgreement.PrivateKey(rawRepresentation: agreementBlob).publicKey.x963Representation == card.agreementKey)
        #expect(try P256.Signing.PrivateKey(rawRepresentation: signingBlob).publicKey.x963Representation == card.signingKey)

        // The ML-KEM blob is the private half of the card's encapsulation key.
        let encapsulation = try #require(bob.pq.encapsulate(peerPublicKeyData: card.mlkemEncapsulationKey))
        #expect(bob.pq.decapsulate(ciphertext: encapsulation.ciphertext, keyBlob: mlkemBlob) == encapsulation.sharedSecret)
    }

    @Test("The card is saved, so a fresh context reads it", .ambientTestKeyManager)
    func savedToStore() throws {
        let bob = try Phone()
        let contact = try bob.contact()
        let card = try bob.cm.createCard(for: contact, now: t0)

        let reread = try ModelContext(bob.container).fetch(FetchDescriptor<Contact.Profile>())
        #expect(reread.compactMap { issuedCard($0.cardState) } == [card.encoded])
    }

    @Test("Expiry is 24 hours on, in whole seconds", .ambientTestKeyManager)
    func expiry() throws {
        let bob = try Phone()
        let contact = try bob.contact()

        let card = try bob.cm.createCard(for: contact, now: Date(timeIntervalSince1970: 1_800_000_000.75))

        #expect(card.expiresAt == Date(timeIntervalSince1970: 1_800_086_400))
        #expect(card.expiresAt.timeIntervalSince1970.truncatingRemainder(dividingBy: 1) == 0)
    }

    @Test("A contact holding an imported or conversation card is refused", .ambientTestKeyManager,
          arguments: ["imported", "conversation"])
    func refusedWhenNotPending(_ kind: String) throws {
        let bob = try Phone()
        let contact = try bob.contact()
        try bob.cm.store(kind == "imported" ? importedState(expiresAt: t0 + day, sent: false) : conversationState(), for: contact)
        let before = contact.introductionCardEncrypted

        #expect(throws: ContactManager.CardError.contactNotPending) { try bob.cm.createCard(for: contact, now: t0) }
        #expect(contact.introductionCardEncrypted == before)
    }

    @Test("A contact with in-person keys is refused", .ambientTestKeyManager)
    func refusedWithInPersonKeys() throws {
        let bob = try Phone()
        let contact = try bob.contact()
        contact.contactPublicKeys = [try inPersonKey()]
        try bob.cm.modelContext.save()
        #expect(contact.hasInPersonKeys, "precondition")

        #expect(throws: ContactManager.CardError.contactNotPending) { try bob.cm.createCard(for: contact, now: t0) }
        #expect(contact.cardState == .empty)
    }

    @Test("Without a post-quantum provider, creating is unsupported", .ambientTestKeyManager)
    func unsupported() throws {
        let bob = try Phone(withPostQuantum: false)
        let contact = try bob.contact()

        #expect(throws: ContactManager.CardError.unsupported) { try bob.cm.createCard(for: contact, now: t0) }
        #expect(contact.cardState == .empty)
    }

    @Test("Creating again replaces the old card, and its keys are gone", .ambientTestKeyManager)
    func createReplaces() throws {
        let bob = try Phone()
        let contact = try bob.contact()
        let first = try bob.cm.createCard(for: contact, now: t0)
        guard case .issued(_, let firstAgreement, let firstSigning, let firstMLKEM, _) = contact.cardState else {
            Issue.record("precondition: issued")
            return
        }

        let second = try bob.cm.createCard(for: contact, now: t0 + hour)

        #expect(second.encoded != first.encoded)
        guard case .issued(let card, let agreement, let signing, let mlkem, _) = contact.cardState else {
            Issue.record("should be issued")
            return
        }
        #expect(card == second.encoded)
        #expect(agreement != firstAgreement && signing != firstSigning && mlkem != firstMLKEM, "none of the old blobs is kept")
        #expect(try bob.cm.ownIssuedAgreementKeys() == [second.agreementKey], "the old card is no longer one of ours")
    }

    @Test("A key-generation failure leaves the previous field intact", .ambientTestKeyManager)
    func failureKeepsPrevious() throws {
        let bob = try Phone()
        let contact = try bob.contact()
        let first = try bob.cm.createCard(for: contact, now: t0)
        let before = try #require(contact.introductionCardEncrypted)

        bob.keys.failing = true
        #expect(throws: SoftwareCardKeys.Failure.injected) { try bob.cm.createCard(for: contact, now: t0 + hour) }
        bob.keys.failing = false

        #expect(contact.introductionCardEncrypted == before, "byte for byte")
        #expect(issuedCard(contact.cardState) == first.encoded)
    }

    @Test("A failure on an empty field leaves it empty and its length unchanged", .ambientTestKeyManager)
    func failureOnEmptyField() throws {
        let bob = try Phone()
        let contact = try bob.contact()
        let before = try #require(contact.introductionCardEncrypted)

        bob.keys.failing = true
        #expect(throws: SoftwareCardKeys.Failure.injected) { try bob.cm.createCard(for: contact, now: t0) }

        #expect(contact.introductionCardEncrypted == before)
        #expect(contact.cardState == .empty)
    }

    @Test("The sealed field keeps one length through create and cancel", .ambientTestKeyManager)
    func lengthStaysFixed() throws {
        let bob = try Phone()
        let contact = try bob.contact()
        let empty = try #require(contact.introductionCardEncrypted).count

        try bob.cm.createCard(for: contact, now: t0)
        #expect(contact.introductionCardEncrypted?.count == empty)

        try bob.cm.cancelCard(for: contact)
        #expect(contact.introductionCardEncrypted?.count == empty)
    }

    @Test("Cancelling an issued card writes empty, and the card is no longer ours", .ambientTestKeyManager)
    func cancel() throws {
        let bob = try Phone()
        let contact = try bob.contact()
        try bob.cm.createCard(for: contact, now: t0)

        try bob.cm.cancelCard(for: contact)

        #expect(contact.cardState == .empty)
        #expect(try bob.cm.ownIssuedAgreementKeys().isEmpty)
    }

    @Test("The share file has a 12-hex name, no extension, and exactly the card's bytes", .ambientTestKeyManager)
    func shareFile() throws {
        let bob = try Phone()
        let contact = try bob.contact()
        let card = try bob.cm.createCard(for: contact, now: t0)

        let url = try bob.cm.cardShareFile(for: contact)
        defer { try? FileManager.default.removeItem(at: url) }

        #expect(url.lastPathComponent.range(of: "^[0-9a-f]{12}$", options: .regularExpression) != nil, "\(url.lastPathComponent)")
        #expect(url.pathExtension.isEmpty)
        #expect(try Data(contentsOf: url) == card.encoded)
        #expect(try Data(contentsOf: url).count == 1_770)
    }

    @Test("Two share files do not share a name", .ambientTestKeyManager)
    func shareFileNamesDiffer() throws {
        let bob = try Phone()
        let contact = try bob.contact()
        try bob.cm.createCard(for: contact, now: t0)

        let first  = try bob.cm.cardShareFile(for: contact)
        let second = try bob.cm.cardShareFile(for: contact)
        defer { try? FileManager.default.removeItem(at: first); try? FileManager.default.removeItem(at: second) }

        #expect(first != second)
    }

    @Test("Sharing needs an issued card", .ambientTestKeyManager, arguments: ["empty", "imported", "conversation"])
    func shareNeedsIssued(_ kind: String) throws {
        let bob = try Phone()
        let contact = try bob.contact()
        switch kind {
        case "imported":     try bob.cm.store(importedState(expiresAt: t0 + day, sent: false), for: contact)
        case "conversation": try bob.cm.store(conversationState(), for: contact)
        default:             break
        }

        #expect(throws: ContactManager.CardError.noIssuedCard) { try bob.cm.cardShareFile(for: contact) }
    }

    @Test("ownIssuedAgreementKeys covers every contact, hidden ones included", .ambientTestKeyManager)
    func ownKeysCoverEveryDepth() throws {
        let bob = try Phone()
        let visible = try bob.contact("Visible")
        let hidden  = try bob.contact("Hidden")
        let first  = try bob.cm.createCard(for: visible, now: t0)
        let second = try bob.cm.createCard(for: hidden, now: t0)
        hidden.visibleThroughDepth = try DepthCodec.encode(0).encrypt()
        try bob.cm.modelContext.save()
        bob.cm.security.applyVerifyState(for: .duress)
        #expect(!hidden.isVisible(atDepth: bob.cm.security.currentDepth), "precondition: hidden at this depth")

        #expect(try bob.cm.ownIssuedAgreementKeys() == [first.agreementKey, second.agreementKey])
    }
}

// MARK: - Import

@MainActor
@Suite("Card — import (SPEC §6.3)", .serialized)
struct CardImportTests {

    // MARK: Success (needs an Enclave: Carol's prekey batch)

    @Test("Carol imports into a pending contact: imported, and ss1/ct1 open on Bob's ML-KEM key",
          .ambientTestKeyManager, .enabled(if: enclave))
    func importIntoPending() throws {
        let bob = try Phone(), carol = try Phone()
        let bobContact = try bob.contact("Carol")
        let card = try bob.cm.createCard(for: bobContact, now: t0)
        guard case .issued(_, _, _, let bobMLKEM, _) = bobContact.cardState else { Issue.record("precondition"); return }
        let carolContact = try carol.contact("Bob")

        let outcome = try carol.cm.importCard(card.encoded, into: carolContact, newContactName: nil, now: t0 + hour)

        #expect(outcome == .imported(contactIdentifier: carolContact.identifier))
        guard case .imported(let peerCard, let agreement, let signing, let mlkem, let ss1, let ct1, let expiresAt, let sent) = carolContact.cardState else {
            Issue.record("the field should hold an imported card")
            return
        }
        #expect(peerCard == card.encoded)
        #expect(expiresAt == card.expiresAt)
        #expect(sent == false)
        #expect(ss1.count == 32)
        #expect(bob.pq.decapsulate(ciphertext: ct1, keyBlob: bobMLKEM) == ss1, "Bob's card ML-KEM key opens Carol's ct1 to her ss1")
        #expect(try P256.KeyAgreement.PrivateKey(rawRepresentation: agreement).publicKey.x963Representation != card.agreementKey)
        _ = try P256.Signing.PrivateKey(rawRepresentation: signing)
        #expect(mlkem.isEmpty == false)
        #expect(carolContact.cardTier == .notVerified)
    }

    @Test("Carol's contact holds a pending own prekey batch afterwards", .ambientTestKeyManager, .enabled(if: enclave))
    func importMakesPendingBatch() throws {
        let bob = try Phone(), carol = try Phone()
        let card = try bob.cm.createCard(for: try bob.contact(), now: t0)
        let carolContact = try carol.contact()

        try carol.cm.importCard(card.encoded, into: carolContact, newContactName: nil, now: t0)

        let record = try carol.cm.prekeyRecord(for: carolContact)
        #expect(record.ownBatches.count == 1)
        #expect(record.ownBatches.first?.isPending == true)
        #expect(record.ownBatches.first?.keys.isEmpty == false)
    }

    @Test("Importing into a new contact creates it with the given name, and the field fixed-length",
          .ambientTestKeyManager, .enabled(if: enclave))
    func importIntoNewContact() throws {
        let bob = try Phone(), carol = try Phone()
        let card = try bob.cm.createCard(for: try bob.contact(), now: t0)
        let emptyLength = try #require(try carol.contact("Existing").introductionCardEncrypted).count

        let outcome = try carol.cm.importCard(card.encoded, into: nil, newContactName: "  Bob  ", now: t0)

        guard case .imported(let identifier) = outcome else { Issue.record("\(outcome)"); return }
        let created = try #require(try carol.cm.fetchContact(by: identifier))
        #expect(created.givenName.decrypt() == "Bob")
        #expect(try carol.cm.fetchAllContacts().count == 2)
        guard case .imported = created.cardState else { Issue.record("should be imported"); return }
        #expect(created.introductionCardEncrypted?.count == emptyLength)
    }

    @Test("A second card from Bob into a waiting contact replaces the first; the old keys and batch are gone",
          .ambientTestKeyManager, .enabled(if: enclave))
    func replace() throws {
        let bob = try Phone(), carol = try Phone()
        let bobContact = try bob.contact()
        let first = try bob.cm.createCard(for: bobContact, now: t0)
        let carolContact = try carol.contact()
        try carol.cm.importCard(first.encoded, into: carolContact, newContactName: nil, now: t0)
        guard case .imported(_, let oldAgreement, let oldSigning, let oldMLKEM, let oldSS1, _, _, _) = carolContact.cardState else {
            Issue.record("precondition"); return
        }
        let oldBatchID = try #require(try carol.cm.prekeyRecord(for: carolContact).ownBatches.first?.id)

        let second = try bob.cm.createCard(for: bobContact, now: t0 + hour)
        let outcome = try carol.cm.importCard(second.encoded, into: carolContact, newContactName: nil, now: t0 + hour)

        #expect(outcome == .imported(contactIdentifier: carolContact.identifier))
        guard case .imported(let peerCard, let agreement, let signing, let mlkem, let ss1, _, _, _) = carolContact.cardState else {
            Issue.record("should be imported"); return
        }
        #expect(peerCard == second.encoded)
        #expect(agreement != oldAgreement && signing != oldSigning && mlkem != oldMLKEM && ss1 != oldSS1, "none of the old material is kept")
        let record = try carol.cm.prekeyRecord(for: carolContact)
        #expect(record.ownBatches.count == 1, "the old import's undelivered batch is dropped, not stacked")
        #expect(record.ownBatches.first?.id != oldBatchID)
    }

    // MARK: Refusals

    @Test("A contact already talking is refused", .ambientTestKeyManager)
    func alreadyTalking() throws {
        let bob = try Phone(), carol = try Phone()
        let card = try bob.cm.createCard(for: try bob.contact(), now: t0)
        let carolContact = try carol.contact()
        try carol.cm.store(conversationState(), for: carolContact)
        let before = carolContact.introductionCardEncrypted

        #expect(try carol.cm.importCard(card.encoded, into: carolContact, newContactName: nil, now: t0) == .refused(.alreadyTalking))
        #expect(carolContact.introductionCardEncrypted == before)
    }

    @Test("Bob importing his own card is refused", .ambientTestKeyManager)
    func ownCard() throws {
        let bob = try Phone()
        let issuedOn = try bob.contact("Issued")
        let other = try bob.contact("Other")
        let card = try bob.cm.createCard(for: issuedOn, now: t0)

        #expect(try bob.cm.importCard(card.encoded, into: other, newContactName: nil, now: t0) == .refused(.ownCard))
        #expect(try bob.cm.importCard(card.encoded, into: issuedOn, newContactName: nil, now: t0) == .refused(.ownCard))
        #expect(try bob.cm.importCard(card.encoded, into: nil, newContactName: "Me", now: t0) == .refused(.ownCard))
        #expect(try bob.cm.fetchAllContacts().count == 2, "a refusal creates no contact")
        #expect(other.cardState == .empty)
    }

    @Test("Bob's own card is refused even when it sits on a contact hidden at a duress depth", .ambientTestKeyManager)
    func ownCardOnHiddenContact() throws {
        let bob = try Phone()
        let hidden = try bob.contact("Hidden")
        let other = try bob.contact("Other")
        let card = try bob.cm.createCard(for: hidden, now: t0)
        hidden.visibleThroughDepth = try DepthCodec.encode(0).encrypt()
        try bob.cm.modelContext.save()
        bob.cm.security.applyVerifyState(for: .duress)
        #expect(!hidden.isVisible(atDepth: bob.cm.security.currentDepth), "precondition: hidden at this depth")

        #expect(try bob.cm.importCard(card.encoded, into: other, newContactName: nil, now: t0) == .refused(.ownCard))
    }

    @Test("An expired card is refused", .ambientTestKeyManager)
    func expired() throws {
        let bob = try Phone(), carol = try Phone()
        let card = try bob.cm.createCard(for: try bob.contact(), now: t0)
        let carolContact = try carol.contact()

        #expect(try carol.cm.importCard(card.encoded, into: carolContact, newContactName: nil, now: card.expiresAt) == .refused(.expired))
        #expect(try carol.cm.importCard(card.encoded, into: carolContact, newContactName: nil, now: t0 + 2 * day) == .refused(.expired))
        #expect(carolContact.cardState == .empty)
    }

    @Test("A contact with in-person keys is refused", .ambientTestKeyManager)
    func inPersonKeysRefused() throws {
        let bob = try Phone(), carol = try Phone()
        let card = try bob.cm.createCard(for: try bob.contact(), now: t0)
        let carolContact = try carol.contact()
        carolContact.contactPublicKeys = [try inPersonKey()]
        try carol.cm.modelContext.save()
        #expect(carolContact.hasInPersonKeys, "precondition")

        #expect(throws: ContactManager.CardError.contactNotPending) {
            try carol.cm.importCard(card.encoded, into: carolContact, newContactName: nil, now: t0)
        }
        #expect(carolContact.cardState == .empty)
    }

    @Test("Bytes that are not a card give notACard, even without a provider", .ambientTestKeyManager)
    func notACard() throws {
        let carol = try Phone()
        let carolContact = try carol.contact()
        #expect(try carol.cm.importCard(randomBytes(1_770), into: carolContact, newContactName: nil, now: t0) == .notACard)
        #expect(try carol.cm.importCard(randomBytes(64), into: carolContact, newContactName: nil, now: t0) == .notACard)
        #expect(try carol.cm.importCard(Data(), into: nil, newContactName: "X", now: t0) == .notACard)
        #expect(carolContact.cardState == .empty)

        let old = try Phone(withPostQuantum: false)
        #expect(try old.cm.importCard(randomBytes(1_770), into: try old.contact(), newContactName: nil, now: t0) == .notACard)
    }

    @Test("Without a post-quantum provider, a real card is unsupported and nothing changes", .ambientTestKeyManager)
    func unsupported() throws {
        let bob = try Phone()
        let card = try bob.cm.createCard(for: try bob.contact(), now: t0)
        let old = try Phone(withPostQuantum: false)
        let oldContact = try old.contact()

        #expect(try old.cm.importCard(card.encoded, into: oldContact, newContactName: nil, now: t0) == .unsupported)
        #expect(try old.cm.importCard(card.encoded, into: nil, newContactName: "Bob", now: t0) == .unsupported)
        #expect(oldContact.cardState == .empty)
        #expect(try old.cm.fetchAllContacts().count == 1)
    }

    @Test("A new contact needs a name, and nothing is created without one", .ambientTestKeyManager,
          arguments: [nil, "", "   \n"] as [String?])
    func nameRequired(_ name: String?) throws {
        let bob = try Phone(), carol = try Phone()
        let card = try bob.cm.createCard(for: try bob.contact(), now: t0)

        #expect(throws: ContactManager.CardError.newContactNameMissing) {
            try carol.cm.importCard(card.encoded, into: nil, newContactName: name, now: t0)
        }
        #expect(try carol.cm.fetchAllContacts().isEmpty)
    }

    // MARK: Crossing cards

    /// Both phones issue to each other, then each imports the other's: exactly one card survives, the one with the
    /// lower agreement key, and both phones agree which.
    @Test("Crossing cards: the lower agreement key survives on both phones", .ambientTestKeyManager, .enabled(if: enclave),
          arguments: 0..<4)
    func crossing(_ attempt: Int) throws {
        let alice = try Phone(), bob = try Phone()
        let aliceContact = try alice.contact("Bob")
        let bobContact   = try bob.contact("Alice")
        let aliceCard = try alice.cm.createCard(for: aliceContact, now: t0)
        let bobCard   = try bob.cm.createCard(for: bobContact, now: t0)

        let aliceOutcome = try alice.cm.importCard(bobCard.encoded, into: aliceContact, newContactName: nil, now: t0 + hour)
        let bobOutcome   = try bob.cm.importCard(aliceCard.encoded, into: bobContact, newContactName: nil, now: t0 + hour)

        let aliceWins = bytewiseLess(aliceCard.agreementKey, bobCard.agreementKey)
        let winner = aliceWins ? aliceCard : bobCard

        // The phone whose card is lower keeps it; the other imports it.
        if aliceWins {
            #expect(aliceOutcome == .refused(.ownCardWins))
            #expect(bobOutcome == .imported(contactIdentifier: bobContact.identifier))
            #expect(issuedCard(aliceContact.cardState) == winner.encoded)
            guard case .imported(let peerCard, _, _, _, _, _, _, _) = bobContact.cardState else { Issue.record("Bob should have imported"); return }
            #expect(peerCard == winner.encoded)
        } else {
            #expect(bobOutcome == .refused(.ownCardWins))
            #expect(aliceOutcome == .imported(contactIdentifier: aliceContact.identifier))
            #expect(issuedCard(bobContact.cardState) == winner.encoded)
            guard case .imported(let peerCard, _, _, _, _, _, _, _) = aliceContact.cardState else { Issue.record("Alice should have imported"); return }
            #expect(peerCard == winner.encoded)
        }
        // The loser's card is no longer one of its own.
        #expect(try (aliceWins ? bob : alice).cm.ownIssuedAgreementKeys().isEmpty)
        // And nothing is left of it in the winner's phone but the winning card.
        #expect(try (aliceWins ? alice : bob).cm.ownIssuedAgreementKeys() == [winner.agreementKey])
    }

    /// The same, with the lower card forced: the winner's phone receives the loser's card and refuses it, the loser's
    /// phone cancels its own. Deterministic, so a regression in the comparison direction cannot hide behind chance.
    @Test("Crossing cards: the phone with the higher card cancels it and imports the lower", .ambientTestKeyManager, .enabled(if: enclave))
    func crossingDeterministic() throws {
        // Keep generating until the two cards are in a known order; each draw is a coin flip.
        var low: (Phone, Contact.Profile, IntroductionCard)?
        var high: (Phone, Contact.Profile, IntroductionCard)?
        for _ in 0..<64 where low == nil {
            let a = try Phone(), b = try Phone()
            let aContact = try a.contact(), bContact = try b.contact()
            let aCard = try a.cm.createCard(for: aContact, now: t0)
            let bCard = try b.cm.createCard(for: bContact, now: t0)
            if bytewiseLess(aCard.agreementKey, bCard.agreementKey) {
                low = (a, aContact, aCard); high = (b, bContact, bCard)
            } else {
                low = (b, bContact, bCard); high = (a, aContact, aCard)
            }
        }
        let (lowPhone, lowContact, lowCard) = try #require(low)
        let (highPhone, highContact, highCard) = try #require(high)

        #expect(try lowPhone.cm.importCard(highCard.encoded, into: lowContact, newContactName: nil, now: t0) == .refused(.ownCardWins))
        #expect(try highPhone.cm.importCard(lowCard.encoded, into: highContact, newContactName: nil, now: t0)
                == .imported(contactIdentifier: highContact.identifier))

        #expect(issuedCard(lowContact.cardState) == lowCard.encoded, "the lower card stays issued")
        guard case .imported(let peerCard, _, _, _, _, _, _, _) = highContact.cardState else { Issue.record("should be imported"); return }
        #expect(peerCard == lowCard.encoded)
        #expect(try highPhone.cm.ownIssuedAgreementKeys().isEmpty, "the higher card was cancelled")
    }
}

// MARK: - Sweep

@MainActor
@Suite("Card — the unlock sweep (SPEC §6.4)", .serialized)
struct CardSweepTests {

    private func record(for contact: Contact.Profile, in cm: ContactManager, _ batches: [PrekeyRecord.OwnBatch]) throws {
        var record = PrekeyRecord.empty
        record.ownBatches = batches
        try cm.store(record, for: contact)
    }

    @Test("An expired issued card is cleared", .ambientTestKeyManager)
    func expiredIssued() throws {
        let bob = try Phone()
        let contact = try bob.contact()
        let card = try bob.cm.createCard(for: contact, now: t0)

        try bob.cm.sweepCards(now: card.expiresAt)

        #expect(contact.cardState == .empty)
        #expect(try bob.cm.ownIssuedAgreementKeys().isEmpty)
    }

    @Test("An unexpired issued card is kept", .ambientTestKeyManager)
    func unexpiredIssued() throws {
        let bob = try Phone()
        let contact = try bob.contact()
        let card = try bob.cm.createCard(for: contact, now: t0)

        try bob.cm.sweepCards(now: card.expiresAt - 1)

        #expect(issuedCard(contact.cardState) == card.encoded)
    }

    @Test("An expired imported card with nothing sent is cleared, and its pending batch with it", .ambientTestKeyManager)
    func expiredImportedNothingSent() throws {
        let carol = try Phone()
        let contact = try carol.contact()
        try carol.cm.store(importedState(expiresAt: t0, sent: false), for: contact)
        let delivered = deliveredBatch()
        try self.record(for: contact, in: carol.cm, [delivered, pendingBatch()])

        try carol.cm.sweepCards(now: t0 + 1)

        #expect(contact.cardState == .empty)
        let record = try carol.cm.prekeyRecord(for: contact)
        #expect(record.ownBatches == [delivered], "only the undelivered batch the import made is dropped")
    }

    @Test("An expired imported card after a first message is kept, with its batch", .ambientTestKeyManager)
    func expiredImportedSent() throws {
        let carol = try Phone()
        let contact = try carol.contact()
        let state = importedState(expiresAt: t0, sent: true)
        try carol.cm.store(state, for: contact)
        let batch = pendingBatch()
        try self.record(for: contact, in: carol.cm, [batch])

        try carol.cm.sweepCards(now: t0 + day)

        #expect(contact.cardState == state)
        #expect(try carol.cm.prekeyRecord(for: contact).ownBatches == [batch])
    }

    @Test("An unexpired imported card is kept, with its batch", .ambientTestKeyManager)
    func unexpiredImported() throws {
        let carol = try Phone()
        let contact = try carol.contact()
        let state = importedState(expiresAt: t0 + day, sent: false)
        try carol.cm.store(state, for: contact)
        let batch = pendingBatch()
        try self.record(for: contact, in: carol.cm, [batch])

        try carol.cm.sweepCards(now: t0)

        #expect(contact.cardState == state)
        #expect(try carol.cm.prekeyRecord(for: contact).ownBatches == [batch])
    }

    @Test("A conversation and an empty field are left alone", .ambientTestKeyManager)
    func conversationAndEmpty() throws {
        let phone = try Phone()
        let talking = try phone.contact("Talking")
        let none = try phone.contact("None")
        let state = conversationState()
        try phone.cm.store(state, for: talking)
        let noneBytes = none.introductionCardEncrypted

        try phone.cm.sweepCards(now: t0 + 30 * day)

        #expect(talking.cardState == state)
        #expect(none.introductionCardEncrypted == noneBytes, "an empty field isn't even rewritten")
    }

    @Test("A contact hidden at a duress depth is swept too", .ambientTestKeyManager)
    func hiddenContactSwept() throws {
        let phone = try Phone()
        let hiddenIssued = try phone.contact("HiddenBob")
        let hiddenImported = try phone.contact("HiddenCarol")
        try phone.cm.store(issuedState(expiresAt: t0), for: hiddenIssued)
        try phone.cm.store(importedState(expiresAt: t0, sent: false), for: hiddenImported)
        for contact in [hiddenIssued, hiddenImported] {
            contact.visibleThroughDepth = try DepthCodec.encode(0).encrypt()
        }
        try phone.cm.modelContext.save()
        phone.cm.security.applyVerifyState(for: .duress)
        #expect(!hiddenIssued.isVisible(atDepth: phone.cm.security.currentDepth), "precondition: hidden at this depth")

        try phone.cm.sweepCards(now: t0 + 1)

        #expect(hiddenIssued.cardState == .empty)
        #expect(hiddenImported.cardState == .empty)
    }

    @Test("A sweep over a mixed population clears only the dead, and no field changes length", .ambientTestKeyManager)
    func mixedPopulation() throws {
        let phone = try Phone()
        let expiredIssued   = try phone.contact("A")
        let liveIssued      = try phone.contact("B")
        let expiredImported = try phone.contact("C")
        let sentImported    = try phone.contact("D")
        let talking         = try phone.contact("E")
        let plain           = try phone.contact("F")
        let liveState = issuedState(expiresAt: t0 + day)
        let sentState = importedState(expiresAt: t0, sent: true)
        try phone.cm.store(issuedState(expiresAt: t0), for: expiredIssued)
        try phone.cm.store(liveState, for: liveIssued)
        try phone.cm.store(importedState(expiresAt: t0, sent: false), for: expiredImported)
        try phone.cm.store(sentState, for: sentImported)
        try phone.cm.store(conversationState(), for: talking)
        let all = [expiredIssued, liveIssued, expiredImported, sentImported, talking, plain]
        let lengthsBefore = all.map { $0.introductionCardEncrypted?.count }
        #expect(Set(lengthsBefore).count == 1, "precondition: one length")

        try phone.cm.sweepCards(now: t0 + hour)

        #expect(expiredIssued.cardState == .empty)
        #expect(expiredImported.cardState == .empty)
        #expect(liveIssued.cardState == liveState)
        #expect(sentImported.cardState == sentState)
        guard case .conversation = talking.cardState else { Issue.record("a conversation survives"); return }
        #expect(all.map { $0.introductionCardEncrypted?.count } == lengthsBefore)
    }

    @Test("The sweep is saved, and a second sweep changes nothing", .ambientTestKeyManager)
    func savedAndIdempotent() throws {
        let phone = try Phone()
        let contact = try phone.contact()
        try phone.cm.store(issuedState(expiresAt: t0), for: contact)
        try phone.cm.modelContext.save()

        try phone.cm.sweepCards(now: t0 + hour)
        let afterFirst = try ModelContext(phone.container).fetch(FetchDescriptor<Contact.Profile>()).map(\.introductionCardEncrypted)
        #expect(try ModelContext(phone.container).fetch(FetchDescriptor<Contact.Profile>()).allSatisfy { $0.cardState == .empty })

        try phone.cm.sweepCards(now: t0 + 2 * hour)
        let afterSecond = try ModelContext(phone.container).fetch(FetchDescriptor<Contact.Profile>()).map(\.introductionCardEncrypted)
        #expect(afterFirst == afterSecond, "a field that is already empty isn't rewritten")
    }
}

// MARK: - E1/E2: tier display, groups, vault trustees

@MainActor
@Suite("Card — what screens make of the tier (E1, E2)", .serialized)
struct CardScreenBehaviourTests {

    @Test("With no keys, an imported or conversation card reads as Not verified", .ambientTestKeyManager,
          arguments: ["imported", "conversation"])
    func notVerified(_ kind: String) throws {
        let phone = try Phone()
        let contact = try phone.contact()
        try phone.cm.store(kind == "imported" ? importedState(expiresAt: t0 + day, sent: false) : conversationState(), for: contact)

        #expect(contact.verificationStatus == .unverified)
    }

    @Test("With no keys, an issued card, an empty field and a nil field read as pending", .ambientTestKeyManager)
    func pending() throws {
        let phone = try Phone()
        let issued = try phone.contact("Issued")
        let empty = try phone.contact("Empty")
        try phone.cm.store(issuedState(expiresAt: t0 + day), for: issued)
        empty.introductionCardEncrypted = nil

        #expect(issued.verificationStatus == .pending)
        #expect(try phone.contact("Plain").verificationStatus == .pending)
        #expect(empty.verificationStatus == .pending)
    }

    @Test("A card Bob issued and Carol imported flow through to the statuses on each phone",
          .ambientTestKeyManager, .enabled(if: enclave))
    func statusesAcrossPhones() throws {
        let bob = try Phone(), carol = try Phone()
        let bobContact = try bob.contact()
        let card = try bob.cm.createCard(for: bobContact, now: t0)
        let carolContact = try carol.contact()
        #expect(bobContact.verificationStatus == .pending)

        try carol.cm.importCard(card.encoded, into: carolContact, newContactName: nil, now: t0)

        #expect(carolContact.verificationStatus == .unverified)
        #expect(bobContact.verificationStatus == .pending, "Bob's contact stays pending until Carol's first message")
    }

    @Test("The hard block applies to imported and conversation only", .ambientTestKeyManager)
    func hardBlockByState() throws {
        let phone = try Phone()
        let key = try #require(try Manager.Ambient.keyManager.createHybridLocalEncryptionKey())
        let states: [(String, CardState, Bool)] = [
            ("empty", .empty, false),
            ("issued", issuedState(expiresAt: t0 + day), false),
            ("imported", importedState(expiresAt: t0 + day, sent: false), true),
            ("imported, sent", importedState(expiresAt: t0 + day, sent: true), true),
            ("conversation", conversationState(), true),
        ]
        for (name, state, blocked) in states {
            let contact = try phone.contact(name)
            try phone.cm.store(state, for: contact)
            #expect(CardRules.isHardBlocked(contact.cardState(using: key)) == blocked, "\(name)")
            #expect(CardRules.isHardBlocked(contact.cardState) == blocked, "\(name)")
        }
    }

    @Test("A nil or unreadable field is not blocked", .ambientTestKeyManager)
    func unreadableNotBlocked() throws {
        let phone = try Phone()
        let key = try #require(try Manager.Ambient.keyManager.createHybridLocalEncryptionKey())
        let nilField = try phone.contact("Nil")
        nilField.introductionCardEncrypted = nil
        let garbage = try phone.contact("Garbage")
        garbage.introductionCardEncrypted = randomBytes(300)

        #expect(CardRules.isHardBlocked(nilField.cardState(using: key)) == false)
        #expect(CardRules.isHardBlocked(garbage.cardState(using: key)) == false)
    }

    /// The group form and the vault trustee list both filter what `mlkemEligibleContacts` returns, or the contacts
    /// the group form partitions, with `CardRules.isHardBlocked(cardState(using:))`. The loops are private to those views, so this runs the
    /// same composition on real stored states: a card contact that would otherwise qualify is excluded.
    @Test("A card contact that holds ML-KEM material is eligible by key but excluded by the hard block", .ambientTestKeyManager)
    func mlkemEligibleAndHardBlock() throws {
        let phone = try Phone()
        let key = try #require(try Manager.Ambient.keyManager.createHybridLocalEncryptionKey())

        func contact(_ name: String, _ state: CardState) throws -> Contact.Profile {
            let contact = try phone.contact(name)
            try phone.cm.store(state, for: contact)
            contact.contactPublicKeys = [Contact.Profile.Key(
                material: try Data(count: 65).encrypt(), owner: try #require(try randomBytes(32).encrypt()),
                date: try #require(try Data("0".utf8).encrypt()),
                quantumKeyMaterialEncrypted: try Data(count: 64).encrypt()
            )]
            return contact
        }
        let ordinary = try contact("Ordinary", .empty)
        let issued   = try contact("Issued", issuedState(expiresAt: t0 + day))
        let talking  = try contact("Talking", conversationState())
        let imported = try contact("Imported", importedState(expiresAt: t0 + day, sent: true))
        try phone.cm.modelContext.save()

        let byKey = phone.cm.mlkemEligibleContacts(usingKey: key).map(\.identifier)
        #expect(Set(byKey) == Set([ordinary, issued, talking, imported].map(\.identifier)), "precondition: all hold ML-KEM material")

        let eligible = phone.cm.mlkemEligibleContacts(usingKey: key).filter { !CardRules.isHardBlocked($0.cardState(using: key)) }.map(\.identifier)
        #expect(Set(eligible) == Set([ordinary, issued].map(\.identifier)))
        #expect(!eligible.contains(talking.identifier) && !eligible.contains(imported.identifier))
    }

    @Test("A card contact is not ML-KEM eligible while it holds no ML-KEM material", .ambientTestKeyManager)
    func cardContactWithoutMLKEMNotEligible() throws {
        let phone = try Phone()
        let key = try #require(try Manager.Ambient.keyManager.createHybridLocalEncryptionKey())
        let contact = try phone.contact()
        try phone.cm.store(conversationState(), for: contact)

        #expect(phone.cm.mlkemEligibleContacts(usingKey: key).isEmpty)
    }
}

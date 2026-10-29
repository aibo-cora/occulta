//
//  CardPhoneSupport.swift
//  OccultaTests
//
//  Two simulated phones for the introduction card suites that follow a conversation into a meeting: each its own
//  `Manager.Ambient` identity and in-memory store, software card keys, in-memory ML-KEM. `CardConversationTests`
//  keeps its own private copy, with the forging helpers that only it needs.
//
//  Anything that makes a prekey batch (importing a card, redeeming one) goes through `PrekeySecretsManager` and
//  needs a Secure Enclave; creating a card does not.
//

import Testing
import Foundation
import SwiftData
import OccultaCore
@testable import Occulta
@testable import OccultaFormats

@MainActor
final class CardPhone {
    let keyManager = TestKeyManager()
    let override: Manager.Ambient.Override
    let cm: ContactManager
    let keys = SoftwareCardKeys()
    let pq: any PostQuantumProvider
    let container: ModelContainer

    init() throws {
        let override = Manager.Ambient.Override(self.keyManager)
        self.override = override
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
        let pq = try #require(PostQuantumProviderFactory.createForTesting())
        self.container = container
        self.pq = pq
        let keys = self.keys
        // Built as this phone, so the manager's own `Manager.Crypto` (which `save` and `update(key:for:)` use) seals
        // under this phone's local DB key, the one every read in `run` opens with.
        self.cm = Manager.Ambient.$override.withValue(override) {
            ContactManager(
                modelContainer: container, security: Manager.Security(modelContainer: container, keyManager: TestKeyManager()),
                cardKeys: keys, cardPostQuantum: pq
            )
        }
    }

    /// Runs `body` as this phone: `Manager.Ambient` is its identity, so its own sealed fields open.
    func run<Result>(_ body: () throws -> Result) throws -> Result {
        try Manager.Ambient.$override.withValue(self.override) { try body() }
    }

    /// A new pending contact; its stored identifier, found by comparing before and after, since it is sealed.
    func newContact(_ name: String, depth: Int = 0) throws -> String {
        try self.run {
            let before = Set(try self.cm.fetchAllContacts().map(\.identifier))
            try self.cm.save(contact: Contact.Draft(identifier: UUID().uuidString, givenName: name, familyName: ""), currentDepth: depth)
            return try #require(try self.cm.fetchAllContacts().first { !before.contains($0.identifier) }).identifier
        }
    }

    /// A contact as an ordinary exchange leaves it: the other phone's identity key, no card.
    func addOrdinary(_ other: CardPhone, as id: String) throws {
        try self.run {
            let profile = Contact.Profile(
                identifier: id, givenName: "", familyName: "", middleName: "",
                nickname: "", organizationName: "", departmentName: "", jobTitle: ""
            )
            profile.contactPublicKeys = [Contact.Profile.Key(
                material: try Manager.Crypto().encrypt(data: try other.keyManager.retrieveIdentity()),
                owner: Data(), date: Data(), quantumKeyMaterialEncrypted: nil
            )]
            let tier = try #require(OccultaBundle.Version.prefixedSenderSignatureCapable.wireByte)
            profile.maxBundleVersion = try Manager.Crypto().encrypt(data: Data([tier]))
            profile.prekeyRecordEncrypted = try PrekeyRecordCodec().encode(.empty).encrypt()
            profile.introductionCardEncrypted = try CardStateCodec().encode(.empty).encrypt()
            try self.cm.insertProfile(profile)
        }
    }

    func contact(_ id: String) throws -> Contact.Profile {
        try #require(try self.cm.fetchContact(by: id))
    }

    func state(_ id: String) throws -> CardState {
        try self.run { try self.contact(id).cardState }
    }

    func store(_ state: CardState, for id: String) throws {
        try self.run {
            try self.cm.store(state, for: try self.contact(id))
            try self.cm.modelContext.save()
        }
    }

    func rawField(_ id: String) throws -> Data? {
        try self.run { try self.contact(id).introductionCardEncrypted }
    }

    func record(_ id: String) throws -> PrekeyRecord {
        try self.run { try self.cm.prekeyRecord(for: try self.contact(id)) }
    }

    func store(_ record: PrekeyRecord, for id: String) throws {
        try self.run {
            try self.cm.store(record, for: try self.contact(id))
            try self.cm.modelContext.save()
        }
    }

    /// The context the key exchange would take from this contact's field.
    func meetingContext(_ id: String) throws -> CardMeetingContext {
        try self.run { self.cm.cardMeetingContext(for: try self.contact(id)) }
    }

    /// Unused one-time keys we hold the private halves of.
    func ownKeyCount(_ id: String) throws -> Int {
        try self.record(id).ownBatches.reduce(0) { $0 + $1.keys.filter { $0.blob != nil }.count }
    }

    /// One-time keys the contact gave us that we have not used.
    func heldKeyCount(_ id: String) throws -> Int {
        try self.record(id).inboundBatches.reduce(0) { $0 + $1.keys.count }
    }

    func hasPendingBatch(_ id: String) throws -> Bool {
        try self.record(id).ownBatches.contains(where: \.isPending)
    }

    func send(to id: String, _ text: String = "hello") throws -> Data {
        try self.run { try self.cm.encryptBundle(basket: Self.basket(text), for: id) }
    }

    @discardableResult
    func receive(_ data: Data) throws -> (ownerID: String, text: String?) {
        try self.run {
            let opened = try self.cm.openGroup(bundle: try OccultaBundle.decoded(from: data))
            let basket = try WireHandle.decode(basket: opened.sealed.message)
            return (opened.ownerID, basket.files.first?.content.flatMap { String(data: $0, encoding: .utf8) })
        }
    }

    static func basket(_ text: String) -> Basket {
        Basket(files: [File(content: Data(text.utf8), format: .text)])
    }
}

/// Bob issues for a pending contact; Carol imports it into a pending contact. Needs an Enclave: Carol's prekey batch.
@MainActor
struct CardPhonePair {
    let bob: CardPhone
    let carol: CardPhone
    let bobSide: String
    let carolSide: String
    let card: IntroductionCard

    init(hiddenAtDuressDepth: Bool = false) throws {
        let bob = try CardPhone(), carol = try CardPhone()
        let bobSide = try bob.newContact("Carol"), carolSide = try carol.newContact("Bob")
        let card = try bob.run { try bob.cm.createCard(for: try bob.contact(bobSide)) }
        let outcome = try carol.run { try carol.cm.importCard(card.encoded, into: try carol.contact(carolSide), newContactName: nil) }
        #expect(outcome == .imported(contactIdentifier: carolSide), "precondition")
        (self.bob, self.carol, self.bobSide, self.carolSide, self.card) = (bob, carol, bobSide, carolSide, card)
        if hiddenAtDuressDepth { try self.hideBobsContact() }
    }

    /// Bob's contact hidden at a duress depth, and the phone at that depth.
    func hideBobsContact() throws {
        try self.bob.run {
            let contact = try self.bob.contact(self.bobSide)
            contact.visibleThroughDepth = try DepthCodec.encode(0).encrypt()
            try self.bob.cm.modelContext.save()
            self.bob.cm.security.applyVerifyState(for: .duress)
            #expect(!contact.isVisible(atDepth: self.bob.cm.security.currentDepth), "precondition: hidden at this depth")
        }
    }

    /// Carol's two bootstrap messages, and Bob opening the second: Bob is a `conversation`, Carol still `imported`
    /// with a first message sent.
    func redeem() throws -> (first: Data, second: Data) {
        let first = try self.carol.send(to: self.carolSide, "first")
        let second = try self.carol.send(to: self.carolSide, "second")
        let opened = try self.bob.receive(second)
        #expect(opened.ownerID == self.bobSide && opened.text == "second")
        return (first, second)
    }

    /// Both sides `conversation`.
    func converse() throws {
        let (first, _) = try self.redeem()
        try self.bob.receive(first)
        try self.carol.receive(try self.bob.send(to: self.bobSide, "reply"))
    }
}

/// What the card says about the contact: computed from the field and the in-person keys, never stored.
@MainActor
func cardTier(of contact: Contact.Profile) -> CardTier {
    CardRules.tier(contact.cardState, hasInPersonKeys: contact.hasInPersonKeys)
}

/// Full material with distinct bytes everywhere, for a stored `conversation`.
func cardTestQuantum() -> QuantumKeyMaterial {
    QuantumKeyMaterial(
        encapsulatedSecret: randomBytes(32), decapsulatedSecret: randomBytes(32),
        ourCiphertext: randomBytes(1_568), peerCiphertext: randomBytes(1_568)
    )
}

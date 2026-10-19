//
//  CardScreenStateTests.swift
//  OccultaTests
//
//  Introduction cards, stage E: what the screens show comes from the card state and the keys, never from the
//  depth (`Docs/Features/Introduction Cards/SPEC.md` §5, §8; Prekey Continuity DESIGN.md §7). The screens
//  themselves are SwiftUI and are not run here. What they read is: `verificationStatus` and `statusAndCard`
//  (the contact lists, the share picker and the classification list all filter on it), `isCardContact`, the
//  group and vault eligibility predicates, and the labels of `VerificationStatus`.
//
//  Skipped, because they are reachable only through a SwiftUI view: the share picker's `List` sections, the
//  classification list's rows, `ContactCardSection`'s body, `CardImportSheet`'s picker and `ComposeHeroV3`'s
//  colours. Group+FormV3's `computeEligibility` and the vault's `mlkemContacts` are private to their views; the
//  tests run the same predicates over the same inputs.
//
//  A contact with in-person keys is judged by `hasInPersonKeys`, which reads the identity through
//  `Manager.Ambient`, so these run on each phone's test identity and need no Enclave. They also check that no
//  real `Manager.Key` was built.
//

import Testing
import Foundation
import CryptoKit
import SwiftData
@testable import Occulta
@testable import OccultaFormats

private let future = Date(timeIntervalSinceNow: 3_600)

private func state(_ name: String) -> CardState {
    switch name {
    case "empty":
        return .empty
    case "issued":
        return .issued(card: randomBytes(1_768), agreementKey: randomBytes(143), signingKey: randomBytes(143),
                       mlkemKey: randomBytes(4_788), expiresAt: future)
    case "imported, unsent", "imported, sent":
        return .imported(peerCard: randomBytes(1_768), agreementKey: randomBytes(143), signingKey: randomBytes(143),
                         mlkemKey: randomBytes(4_788), ss1: randomBytes(32), ct1: randomBytes(1_568),
                         expiresAt: future, sentFirstMessage: name == "imported, sent")
    default:
        return .conversation(agreementKey: randomBytes(143), signingKey: randomBytes(143), peerAgreementKey: randomBytes(65),
                             peerSigningKey: randomBytes(65), quantum: cardTestQuantum(), bootstrapOpen: false, isIssuer: false)
    }
}

private let stateNames = ["empty", "issued", "imported, unsent", "imported, sent", "conversation"]

/// The status the table in FINDINGS §3 gives each state with no keys: only a card in use is Not verified.
private func expectedWithoutKeys(_ name: String) -> VerificationStatus {
    ["imported, unsent", "imported, sent", "conversation"].contains(name) ? .unverified : .pending
}

@MainActor
private func makeContact(on phone: CardPhone, name: String, card: CardState?) throws -> String {
    let id = try phone.newContact(name)
    if let card { try phone.store(card, for: id) }
    return id
}

// MARK: - Status without keys

@MainActor
@Suite("Screen state — the status a card gives a contact with no keys", .serialized)
struct CardStatusWithoutKeysTests {

    @Test("verificationStatus and statusAndCard follow the card state", .ambientTestKeyManager, arguments: stateNames)
    func status(_ name: String) throws {
        let phone = try CardPhone()
        let id = try makeContact(on: phone, name: "Pat", card: state(name))
        let read = try phone.run { try phone.contact(id).statusAndCard }

        #expect(read.status == expectedWithoutKeys(name), "\(name)")
        #expect(read.card != nil, "the card was read to decide, and is handed back so a screen decrypts once")
        #expect(try phone.run { try phone.contact(id).verificationStatus } == read.status)
        #expect(try phone.run { cardTier(of: try phone.contact(id)) } == (read.status == .unverified ? .notVerified : .pending))
    }

    @Test("A nil or unreadable card field is pending, as a contact that never had a card", .ambientTestKeyManager)
    func unreadable() throws {
        let phone = try CardPhone()
        let nilField = try makeContact(on: phone, name: "Nil", card: nil)
        try phone.run { try phone.contact(nilField).introductionCardEncrypted = nil }
        let garbage = try makeContact(on: phone, name: "Garbage", card: nil)
        try phone.run { try phone.contact(garbage).introductionCardEncrypted = randomBytes(300) }

        #expect(try phone.run { try phone.contact(nilField).verificationStatus } == .pending)
        #expect(try phone.run { try phone.contact(garbage).verificationStatus } == .pending)
    }

    @Test("isCardContact is true for exactly the states the card section replaces 'No key yet' for", arguments: stateNames)
    func isCardContact(_ name: String) {
        #expect(state(name).isCardContact == (expectedWithoutKeys(name) == .unverified), "\(name)")
    }

    @Test("Not verified is never green, and reads the one label everywhere")
    func labels() {
        #expect(VerificationStatus.unverified.color != VerificationStatus.verified.color)
        #expect(VerificationStatus.unverified.sectionLabel == IntroCardCopy.notVerifiedChip.uppercased())
        #expect(VerificationStatus.unverified.chipLabel.contains(IntroCardCopy.notVerifiedChip.uppercased()))
        #expect(!VerificationStatus.unverified.chipLabel.contains("UNVERIFIED"))
    }

    /// The share picker, the contact list and the classification list each partition contacts by this status.
    @Test("Every contact lands in exactly one of the three lists, and card contacts in Not verified", .ambientTestKeyManager)
    func partition() throws {
        let phone = try CardPhone()
        let ids = try stateNames.map { try makeContact(on: phone, name: $0, card: state($0)) }
        let contacts = try phone.run { try ids.map { try phone.contact($0) } }
        let statuses = try phone.run {
            Dictionary(contacts.map { ($0.identifier, $0.verificationStatus) }, uniquingKeysWith: { first, _ in first })
        }
        let verified   = contacts.filter { statuses[$0.identifier] == .verified }
        let unverified = contacts.filter { statuses[$0.identifier] == .unverified }
        let pending    = contacts.filter { statuses[$0.identifier] == .pending }

        #expect(verified.count + unverified.count + pending.count == contacts.count)
        #expect(verified.isEmpty)
        #expect(unverified.count == 3 && pending.count == 2)
    }
}

// MARK: - Status with keys

@MainActor
@Suite("Screen state — keys outrank the card", .serialized)
struct CardStatusWithKeysTests {

    /// A contact holding one key whose owner hash is `ownerHash`, as an exchange writes it.
    private func contact(on phone: CardPhone, card: CardState, ownerHash: Data, expired: Bool = false) throws -> String {
        let id = try phone.newContact("Pat")
        try phone.store(card, for: id)
        try phone.run {
            let profile = try phone.contact(id)
            let key = Contact.Profile.Key(
                material: try Data(count: 65).encrypt(),
                owner: try #require(try ownerHash.encrypt()),
                date: try #require(try Data("0".utf8).encrypt())
            )
            if expired { key.expiredOn = try Data("1".utf8).encrypt() }
            profile.contactPublicKeys = [key]
            try phone.cm.modelContext.save()
        }
        return id
    }

    /// The owner hash an exchange on this phone writes: our identity key, through the ambient seam.
    private func ownerHash(_ phone: CardPhone) throws -> Data {
        try phone.keyManager.retrieveIdentity().sha256
    }

    /// `statusAndCard` reads the identity through `Manager.Ambient`: no real `Manager.Key` is ever built, so
    /// these need no Enclave.
    private func expectNoRealKey(_ phone: CardPhone) {
        #expect(phone.override.realKeyConstructions == 0, "a real Manager.Key was built under this phone's override")
    }

    @Test("In-person keys: Verified, whatever the card says", arguments: stateNames)
    func verified(_ name: String) throws {
        let phone = try CardPhone()
        let id = try self.contact(on: phone, card: state(name), ownerHash: try self.ownerHash(phone))
        let read = try phone.run { try phone.contact(id).statusAndCard }
        #expect(read.status == .verified, "\(name)")
        #expect(read.card == nil, "\(name): a contact with keys never pays for the card field's decryption")
        self.expectNoRealKey(phone)
    }

    @Test("Keys from another identity: Not verified, whatever the card says (a shared or transferred key is never green)",
          arguments: stateNames)
    func otherOwner(_ name: String) throws {
        let phone = try CardPhone()
        let id = try self.contact(on: phone, card: state(name), ownerHash: randomBytes(32))
        #expect(try phone.run { try phone.contact(id).verificationStatus } == .unverified, "\(name)")
        self.expectNoRealKey(phone)
    }

    @Test("An expired last key falls back to the card", arguments: stateNames)
    func expiredKey(_ name: String) throws {
        let phone = try CardPhone()
        let id = try self.contact(on: phone, card: state(name), ownerHash: try self.ownerHash(phone), expired: true)
        #expect(try phone.run { try phone.contact(id).verificationStatus } == expectedWithoutKeys(name), "\(name)")
    }

    @Test("The same status at a duress depth, for a visible and for a hidden contact", arguments: stateNames)
    func sameAtDuressDepth(_ name: String) throws {
        let phone = try CardPhone()
        let plain = try makeContact(on: phone, name: "Plain", card: state(name))
        let hidden = try makeContact(on: phone, name: "Hidden", card: state(name))
        let keyed = try self.contact(on: phone, card: state(name), ownerHash: try self.ownerHash(phone))
        let ids = [plain, hidden, keyed]
        let atRealDepth = try phone.run { try ids.map { try phone.contact($0).verificationStatus } }

        try phone.run {
            try phone.contact(hidden).visibleThroughDepth = try DepthCodec.encode(0).encrypt()
            try phone.cm.modelContext.save()
            phone.cm.security.applyVerifyState(for: .duress)
        }
        #expect(try phone.run { phone.cm.security.currentDepth } != 0, "precondition: a duress depth")
        #expect(try phone.run { try ids.map { try phone.contact($0).verificationStatus } } == atRealDepth, "\(name)")
        #expect(atRealDepth == [expectedWithoutKeys(name), expectedWithoutKeys(name), .verified], "\(name)")
        self.expectNoRealKey(phone)
    }
}

// MARK: - Depth independence of the card tier

@MainActor
@Suite("Screen state — the card tier and eligibility don't read the depth", .serialized)
struct CardEligibilityTests {

    private func groupCapable(_ phone: CardPhone, _ id: String) throws {
        try phone.run {
            let tier = try #require(OccultaBundle.Version.groupCapable.wireByte)
            try phone.contact(id).maxBundleVersion = try Manager.Crypto().encrypt(data: Data([tier]))
            try phone.cm.modelContext.save()
        }
    }

    private func withMLKEM(_ phone: CardPhone, _ id: String) throws {
        try phone.run {
            try phone.contact(id).contactPublicKeys = [Contact.Profile.Key(
                material: try Data(count: 65).encrypt(), owner: try Data(count: 32).encrypt() ?? Data(),
                date: try #require(try Data("0".utf8).encrypt()), quantumKeyMaterialEncrypted: try Data(count: 64).encrypt()
            )]
            try phone.cm.modelContext.save()
        }
    }

    @Test("Group eligibility refuses imported and conversation, and only those, at depth 0 and at a duress depth",
          .ambientTestKeyManager, arguments: stateNames)
    func groupEligibility(_ name: String) throws {
        let phone = try CardPhone()
        let id = try makeContact(on: phone, name: "Pat", card: state(name))
        try self.groupCapable(phone, id)
        let blocked = expectedWithoutKeys(name) == .unverified

        func read() throws -> (eligible: Bool, reason: IneligibilityReason?) {
            try phone.run { (try phone.cm.isGroupEligible(identifier: id), try phone.cm.groupIneligibilityReason(for: id)) }
        }
        let atRealDepth = try read()
        #expect(atRealDepth.eligible == !blocked, "\(name)")
        #expect((atRealDepth.reason == .cardConversation) == blocked, "\(name)")

        try phone.run {
            try phone.contact(id).visibleThroughDepth = try DepthCodec.encode(0).encrypt()
            try phone.cm.modelContext.save()
            phone.cm.security.applyVerifyState(for: .duress)
        }
        let atDuress = try read()
        #expect(atDuress.eligible == atRealDepth.eligible && atDuress.reason == atRealDepth.reason, "\(name): the depth changes nothing")
    }

    /// The vault trustee list is `mlkemEligibleContacts(usingKey:)` minus the contacts the card hard-blocks.
    @Test("The vault trustee filter keeps empty and issued, drops imported and conversation, at either depth",
          .ambientTestKeyManager)
    func vaultFilter() throws {
        let phone = try CardPhone()
        let ids = try stateNames.map { name -> String in
            let id = try makeContact(on: phone, name: name, card: state(name))
            try self.withMLKEM(phone, id)
            return id
        }

        func trustees() throws -> Set<String> {
            try phone.run {
                let key = try #require(try Manager.Ambient.keyManager.createHybridLocalEncryptionKey())
                return Set(phone.cm.mlkemEligibleContacts(usingKey: key)
                    .filter { !$0.cardState(using: key).isCardContact }.map(\.identifier))
            }
        }
        let expected = Set([ids[0], ids[1]])
        #expect(try trustees() == expected)

        try phone.run { phone.cm.security.applyVerifyState(for: .duress) }
        #expect(try trustees() == expected, "the depth changes nothing about who is blocked")
    }

    @Test("The tier computed from a state never changes with the depth", .ambientTestKeyManager, arguments: stateNames)
    func tierIgnoresDepth(_ name: String) throws {
        let phone = try CardPhone()
        let id = try makeContact(on: phone, name: "Pat", card: state(name))
        let before = try phone.run { cardTier(of: try phone.contact(id)) }
        try phone.run { phone.cm.security.applyVerifyState(for: .duress) }
        #expect(try phone.run { cardTier(of: try phone.contact(id)) } == before, "\(name)")
        #expect(before == CardRules.tier(state(name), hasInPersonKeys: false), "\(name)")
    }
}

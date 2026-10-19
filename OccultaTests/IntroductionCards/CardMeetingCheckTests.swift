//
//  CardMeetingCheckTests.swift
//  OccultaTests
//
//  Introduction cards, stage D: the meeting check (`Docs/Features/Introduction Cards/SPEC.md` §7). Each row of the
//  table is run with real card states from two simulated phones: both phones build their `CardMeetingContext` from
//  their own field, a synthetic ceremony result is mirrored between them, each signs its proof with its context,
//  and each computes its verdict with `CardMeetingContext.verdict`. The proof message, the save path
//  (`update(key:for:)`), and what the save leaves alone follow.
//
//  The rows that need a conversation make a prekey batch through `PrekeySecretsManager` and carry
//  `.enabled(if:)`. The message and the save of a card that is `empty` or `issued` run anywhere.
//
//  Not covered here: `ExchangeManager`'s own state machine (`sendCardProof`, the `isCardProof` branch of its
//  receive handler). It needs a Multipeer session and Nearby Interaction, which a unit test can't open. What it
//  calls is covered: `CardMeetingContext.verdict`, the context, the `Exchange` message and the save.
//

import Testing
import Foundation
import CryptoKit
import NearbyInteraction
import SwiftData
@testable import Occulta
@testable import OccultaFormats

private let enclave = TestSupport.secureEnclaveAvailable()

// MARK: - A synthetic ceremony

private enum Side { case bob, carol }

/// What both sides hold identically once the ML-KEM step completes, mirrored for each.
private struct Ceremony {
    let bobIdentity   = Data([0x04]) + randomBytes(64)
    let carolIdentity = Data([0x04]) + randomBytes(64)
    let bobNonce      = randomBytes(16)
    let carolNonce    = randomBytes(16)
    let bobCiphertext   = randomBytes(1_568)
    let carolCiphertext = randomBytes(1_568)

    func identity(_ side: Side) -> Data { side == .bob ? self.bobIdentity : self.carolIdentity }

    /// This side's `HybridExchangeResult`: ours first, theirs second.
    func result(_ side: Side) -> ExchangeManager.HybridExchangeResult {
        let (ours, theirs) = side == .bob
            ? (self.bobIdentity, self.carolIdentity) : (self.carolIdentity, self.bobIdentity)
        return ExchangeManager.HybridExchangeResult(
            peerP256PublicKey: theirs,
            mlkemSecret1: Data(repeating: 1, count: 32), mlkemSecret2: Data(repeating: 2, count: 32),
            ourNonce: side == .bob ? self.bobNonce : self.carolNonce,
            peerNonce: side == .bob ? self.carolNonce : self.bobNonce,
            ourCiphertext: side == .bob ? self.bobCiphertext : self.carolCiphertext,
            peerCiphertext: side == .bob ? self.carolCiphertext : self.bobCiphertext
        )
    }

    var transcript: Data {
        CardMeeting.transcript(
            identityKeys: (self.bobIdentity, self.carolIdentity),
            nonces: (self.bobNonce, self.carolNonce),
            mlkemCiphertexts: (self.bobCiphertext, self.carolCiphertext)
        )
    }

    /// The proof message `sendCardProof` sends: signed when the context holds a key, else filler.
    func proof(_ side: Side, _ context: CardMeetingContext) -> Data {
        let signed = try? context.sign?(CardMeeting.proofPayload(transcript: self.transcript, signerIdentityKey: self.identity(side)))
        return signed.flatMap { $0.count == CardMeeting.proofByteCount ? $0 : nil } ?? CardMeeting.filler()
    }

    func verdict(_ side: Side, _ context: CardMeetingContext, peerProof: Data?) -> CardMeetingVerdict {
        CardMeetingContext.verdict(context: context, result: self.result(side), ourIdentity: self.identity(side), peerProof: peerProof)
    }

    /// Both verdicts, each side getting the other's honest proof.
    @MainActor
    func verdicts(_ pair: CardPhonePair) throws -> (bob: CardMeetingVerdict, carol: CardMeetingVerdict) {
        let bob = try pair.bob.meetingContext(pair.bobSide), carol = try pair.carol.meetingContext(pair.carolSide)
        return (
            self.verdict(.bob, bob, peerProof: self.proof(.carol, carol)),
            self.verdict(.carol, carol, peerProof: self.proof(.bob, bob))
        )
    }
}

// MARK: - SPEC §7's table

@MainActor
@Suite("Meeting check — every row of SPEC §7's table", .serialized, .enabled(if: enclave))
struct CardMeetingTableTests {

    /// (setup name, Bob's verdict, Carol's verdict)
    static let rows: [(String, CardMeetingVerdict, CardMeetingVerdict)] = [
        ("both conversation", .match, .match),
        ("Carol sent, Bob still issued", .none, .match),
        ("Carol sent, Bob conversation", .match, .match),
        ("issued, imported before any send", .none, .none),
        ("issued, Carol empty", .none, .none),
        ("Carol conversation, Bob empty", .none, .mismatch),
        ("Carol sent, Bob empty", .none, .mismatch),
        ("Bob conversation, Carol empty", .mismatch, .none),
        ("both empty", .none, .none),
    ]

    private func setUp(_ name: String) throws -> CardPhonePair {
        let pair = try CardPhonePair()
        switch name {
        case "both conversation":
            try pair.converse()
        case "Carol sent, Bob still issued":
            _ = try pair.carol.send(to: pair.carolSide)
        case "Carol sent, Bob conversation":
            _ = try pair.redeem()
        case "issued, imported before any send":
            break
        case "issued, Carol empty":
            try pair.carol.store(CardState.empty, for: pair.carolSide)
        case "Carol conversation, Bob empty":
            try pair.converse()
            try pair.bob.store(CardState.empty, for: pair.bobSide)
        case "Carol sent, Bob empty":
            _ = try pair.carol.send(to: pair.carolSide)
            try pair.bob.run { try pair.bob.cm.cancelCard(for: try pair.bob.contact(pair.bobSide)) }
        case "Bob conversation, Carol empty":
            _ = try pair.redeem()
            try pair.carol.store(CardState.empty, for: pair.carolSide)
        case "both empty":
            try pair.bob.store(CardState.empty, for: pair.bobSide)
            try pair.carol.store(CardState.empty, for: pair.carolSide)
        default:
            Issue.record("unknown row \(name)")
        }
        return pair
    }

    @Test("Each row shows what the table says, on each side", arguments: rows.map(\.0))
    func row(_ name: String) throws {
        let expected = try #require(Self.rows.first { $0.0 == name })
        let pair = try self.setUp(name)
        let verdicts = try Ceremony().verdicts(pair)

        #expect(verdicts.bob == expected.1, "\(name): Bob")
        #expect(verdicts.carol == expected.2, "\(name): Carol")
    }

    /// The row the table singles out: Carol has written and not yet heard back, Bob has redeemed. Bob's field is a
    /// `conversation` and Carol's is not, but Carol's proof is real, so Bob must not see a false W-11.
    @Test("Carol imported with a message sent, Bob conversation: W-12 on both, no false W-11")
    func noFalseMismatch() throws {
        let pair = try CardPhonePair()
        _ = try pair.redeem()
        guard case .imported(_, _, _, _, _, _, _, true) = try pair.carol.state(pair.carolSide),
              case .conversation = try pair.bob.state(pair.bobSide) else { Issue.record("precondition"); return }

        let verdicts = try Ceremony().verdicts(pair)
        #expect(verdicts.bob == .match && verdicts.carol == .match)
    }

    @Test("Every state signs, but only an empty field sends a filler")
    func signsWheneverItHoldsAKey() throws {
        let pair = try CardPhonePair()
        // Bob issued, Carol imported before a send.
        #expect(try pair.bob.meetingContext(pair.bobSide).sign != nil)
        #expect(try pair.carol.meetingContext(pair.carolSide).sign != nil)
        _ = try pair.carol.send(to: pair.carolSide)
        #expect(try pair.carol.meetingContext(pair.carolSide).sign != nil)
        try pair.bob.store(CardState.empty, for: pair.bobSide)
        #expect(try pair.bob.meetingContext(pair.bobSide).sign == nil)
        #expect(try pair.bob.meetingContext(pair.bobSide).peerSigningKey == nil)
    }

    @Test("Only imported-after-sending and conversation hold a key to judge by")
    func peerKeyOnlyWhereTableShowsAVerdict() throws {
        let pair = try CardPhonePair()
        #expect(try pair.bob.meetingContext(pair.bobSide).peerSigningKey == nil, "issued")
        #expect(try pair.carol.meetingContext(pair.carolSide).peerSigningKey == nil, "imported before a send")
        _ = try pair.redeem()
        #expect(try pair.carol.meetingContext(pair.carolSide).peerSigningKey == pair.card.signingKey, "imported after a send: Bob's card signing key")
        let bobKey = try #require(try pair.bob.meetingContext(pair.bobSide).peerSigningKey)
        guard case .conversation(_, _, _, let stored, _, _, _) = try pair.bob.state(pair.bobSide) else { Issue.record("precondition"); return }
        #expect(bobKey == stored, "conversation: the stored peerSigningKey")
    }

    // MARK: Mismatches

    @Test("A proof that doesn't verify is W-11 on the side that judges, and doesn't change the other side's W-12",
          arguments: ["badSignature", "otherTranscript", "otherIdentity", "missing", "reflected", "otherSigningKey", "wrongLength", "filler"])
    func mismatch(_ kind: String) throws {
        let pair = try CardPhonePair()
        try pair.converse()
        let ceremony = Ceremony()
        let bob = try pair.bob.meetingContext(pair.bobSide), carol = try pair.carol.meetingContext(pair.carolSide)
        let honestCarol = ceremony.proof(.carol, carol)
        let honestBob = ceremony.proof(.bob, bob)

        // Carol's proof as Bob receives it.
        let received: Data?
        switch kind {
        case "badSignature":
            var flipped = honestCarol
            flipped[flipped.startIndex + 10] ^= 0x01
            received = flipped
        case "otherTranscript":
            // A real signature by Carol's card key, over another ceremony's transcript.
            let other = Ceremony()
            received = try carol.sign?(CardMeeting.proofPayload(transcript: other.transcript, signerIdentityKey: ceremony.carolIdentity))
        case "otherIdentity":
            // Bound to an identity key that isn't the one she sent.
            received = try carol.sign?(CardMeeting.proofPayload(transcript: ceremony.transcript, signerIdentityKey: Data([0x04]) + randomBytes(64)))
        case "missing":
            received = nil
        case "reflected":
            // Bob's own proof sent back to him.
            received = honestBob
        case "otherSigningKey":
            // Correct payload, signed by a key that isn't the card's.
            let impostor = SoftwareCardKeys()
            let blob = try impostor.makeSigningKey().blob
            received = try impostor.signRaw(CardMeeting.proofPayload(transcript: ceremony.transcript, signerIdentityKey: ceremony.carolIdentity), signingBlob: blob)
        case "wrongLength":
            received = honestCarol.dropLast()
        case "filler":
            received = CardMeeting.filler()
        default:
            Issue.record("unknown kind \(kind)")
            return
        }

        #expect(ceremony.verdict(.bob, bob, peerProof: received) == .mismatch, "\(kind)")
        #expect(ceremony.verdict(.bob, bob, peerProof: honestCarol) == .match, "control: the honest proof matches")
        #expect(ceremony.verdict(.carol, carol, peerProof: honestBob) == .match, "Carol's own check is independent of Bob's")
    }

    @Test("Carol, imported after sending, judges Bob's proof against his card's signing key", arguments: ["badSignature", "missing", "filler"])
    func carolMismatch(_ kind: String) throws {
        let pair = try CardPhonePair()
        _ = try pair.redeem()
        let ceremony = Ceremony()
        let bob = try pair.bob.meetingContext(pair.bobSide), carol = try pair.carol.meetingContext(pair.carolSide)
        var proof: Data? = ceremony.proof(.bob, bob)
        switch kind {
        case "badSignature":
            var flipped = try #require(proof)
            flipped[flipped.startIndex + 3] ^= 0x01
            proof = flipped
        case "missing":      proof = nil
        default:             proof = CardMeeting.filler()
        }
        #expect(ceremony.verdict(.carol, carol, peerProof: proof) == .mismatch)
    }

    @Test("A proof for a different ceremony isn't accepted by a side with the same keys")
    func proofIsBoundToTheTranscript() throws {
        let pair = try CardPhonePair()
        try pair.converse()
        let first = Ceremony(), second = Ceremony()
        let bob = try pair.bob.meetingContext(pair.bobSide), carol = try pair.carol.meetingContext(pair.carolSide)
        #expect(first.verdict(.bob, bob, peerProof: second.proof(.carol, carol)) == .mismatch, "a replay from another meeting")
    }

    // MARK: Classical-only

    @Test("A classical-only exchange has no transcript: no verdict in any row", arguments: rows.map(\.0))
    func classicalOnly(_ name: String) throws {
        let pair = try self.setUp(name)
        let ceremony = Ceremony()
        let bob = try pair.bob.meetingContext(pair.bobSide), carol = try pair.carol.meetingContext(pair.carolSide)

        let bobVerdict = CardMeetingContext.verdict(context: bob, result: nil, ourIdentity: ceremony.bobIdentity, peerProof: ceremony.proof(.carol, carol))
        let carolVerdict = CardMeetingContext.verdict(context: carol, result: nil, ourIdentity: ceremony.carolIdentity, peerProof: ceremony.proof(.bob, bob))
        #expect(bobVerdict == .none && carolVerdict == .none, "\(name)")
    }

    @Test("Without the identity key we sent there is nothing to check against")
    func noIdentityNoVerdict() throws {
        let pair = try CardPhonePair()
        try pair.converse()
        let ceremony = Ceremony()
        let bob = try pair.bob.meetingContext(pair.bobSide), carol = try pair.carol.meetingContext(pair.carolSide)
        #expect(CardMeetingContext.verdict(context: bob, result: ceremony.result(.bob), ourIdentity: nil, peerProof: ceremony.proof(.carol, carol)) == .none)
    }
}

// MARK: - The proof message

/// The `Exchange` of the build before the meeting check: no `cardProof` key, and `isDiscovery` as it was.
private struct LegacyExchange: Codable {
    let id: String
    let token: Data
    let version: Version
    let identity: Data?
    let nonce: Data?
    let encapsulationKey: Data?
    let ciphertext: Data?

    enum Version: Int8, Codable { case v1 = 1, v2pq = 2 }

    var isDiscovery: Bool { self.identity == nil && self.ciphertext == nil }
    var isIdentity: Bool { self.identity != nil && self.ciphertext == nil }
    var isCiphertext: Bool { self.ciphertext != nil }
}

@Suite("Meeting check — the proof message", .serialized)
struct CardProofMessageTests {

    @MainActor
    @Test("Ending an exchange drops the card's meeting context: the signing blob and the peer's key")
    func finishDropsContext() {
        let manager = ExchangeManager()
        manager.cardMeeting = CardMeetingContext(sign: { $0 }, peerSigningKey: randomBytes(65))
        manager.finish()
        #expect(manager.cardMeeting.sign == nil)
        #expect(manager.cardMeeting.peerSigningKey == nil)
    }

    private func realProof() throws -> Data {
        let keys = SoftwareCardKeys()
        return try keys.signRaw(Data("payload".utf8), signingBlob: try keys.makeSigningKey().blob)
    }

    /// Foundation writes `/` as `\/`, and base64 of random bytes holds a `/` about one time in 64, so the JSON of any
    /// message with random bytes in it varies by a few characters from one draw to the next. That is the same for a
    /// signature and a filler, since both are 64 uniformly random-looking bytes. With the escapes undone, the length is
    /// the same every time.
    @Test("A real signature and a filler encode to the same length, over many draws")
    func sameLength() throws {
        var real = Set<Int>(), filler = Set<Int>(), unescaped = Set<Int>()
        for _ in 0..<200 {
            for (isReal, proof) in [(true, try self.realProof()), (false, CardMeeting.filler())] {
                let json = try JSONEncoder().encode(Exchange(id: UUID().uuidString, token: Data(), version: .v1, cardProof: proof))
                let text = try #require(String(data: json, encoding: .utf8))
                if isReal { real.insert(json.count) } else { filler.insert(json.count) }
                unescaped.insert(text.replacingOccurrences(of: "\\/", with: "/").utf8.count)
                #expect(proof.count == CardMeeting.proofByteCount)
                #expect(proof.base64EncodedString().count == 88, "the proof field is the same width either way")
            }
        }
        #expect(unescaped.count == 1, "lengths without escapes: \(unescaped)")
        #expect(real.isSubset(of: filler.union(real)) && !real.isEmpty && !filler.isEmpty)
        #expect(real.min()! >= unescaped.first! && filler.min()! >= unescaped.first!)
        #expect(real.max()! - real.min()! <= 12 && filler.max()! - filler.min()! <= 12, "only the slash escapes vary")
        #expect(abs(Double(real.reduce(0, +)) / Double(real.count) - Double(filler.reduce(0, +)) / Double(filler.count)) < 3,
                "the same spread for both")
    }

    @Test("A proof is a proof and not a discovery, identity or ciphertext message")
    func classification() throws {
        let proof = Exchange(id: UUID().uuidString, token: Data(), version: .v1, cardProof: CardMeeting.filler())
        #expect(proof.isCardProof)
        #expect(!proof.isDiscovery)
        #expect(!proof.isIdentity)
        #expect(!proof.isCiphertext)
        let decoded = try JSONDecoder().decode(Exchange.self, from: try JSONEncoder().encode(proof))
        #expect(decoded.isCardProof && !decoded.isDiscovery)
        #expect(decoded.cardProof == proof.cardProof)
        #expect(decoded.token.isEmpty && decoded.identity == nil && decoded.ciphertext == nil && decoded.nonce == nil)
    }

    @Test("Ordinary ceremony messages are unchanged: no proof key on the wire, same classification")
    func ordinaryMessagesUnchanged() throws {
        let discovery = Exchange(id: UUID().uuidString, token: Data([1, 2, 3]))
        let identity = Exchange(id: UUID().uuidString, token: Data(), identity: Data([4]), nonce: Data(count: 16), encapsulationKey: Data(count: 8))
        let ciphertext = Exchange(id: UUID().uuidString, token: Data(), ciphertext: Data(count: 8))
        #expect(discovery.isDiscovery && !discovery.isCardProof)
        #expect(identity.isIdentity && !identity.isCardProof && !identity.isDiscovery)
        #expect(ciphertext.isCiphertext && !ciphertext.isCardProof && !ciphertext.isDiscovery)
        for message in [discovery, identity, ciphertext] {
            let json = try #require(String(data: try JSONEncoder().encode(message), encoding: .utf8))
            #expect(!json.contains("cardProof"), "a message without a proof is byte-compatible with the build before")
        }
    }

    @Test("An older decoder reads a proof as a discovery whose empty token fails to unarchive")
    func olderDecoderDropsIt() throws {
        let proof = Exchange(id: UUID().uuidString, token: Data(), version: .v1, cardProof: try self.realProof())
        let legacy = try JSONDecoder().decode(LegacyExchange.self, from: try JSONEncoder().encode(proof))

        #expect(legacy.isDiscovery, "the older build routes it to the discovery handler")
        #expect(!legacy.isIdentity && !legacy.isCiphertext)
        #expect(legacy.token.isEmpty)
        // That handler unarchives the token; an empty one is no token, so the message is dropped.
        let token = try? NSKeyedUnarchiver.unarchivedObject(ofClass: NIDiscoveryToken.self, from: legacy.token)
        #expect(token == nil)
    }
}

// MARK: - The save

/// A key the exchange stores: `Contact.Draft.Key` hashes the owner identity itself.
private func inPersonKey(for identity: Data) throws -> Contact.Draft.Key {
    try #require(Contact.Draft.Key(material: Data([0x04]) + randomBytes(64), owner: identity, date: "1"))
}

/// A filler record with the card-era contents in it.
private func busyRecord() -> PrekeyRecord {
    var record = PrekeyRecord.empty
    record.ownBatches = [PrekeyRecord.OwnBatch(
        id: randomBytes(16), createdAt: Date(timeIntervalSince1970: 1_800_000_000), retiredAt: nil, isPending: true,
        keys: (0..<3).map { _ in PrekeyRecord.OwnKey(id: randomBytes(16), blob: randomBytes(143), publicKey: nil) }
    )]
    record.inboundBatches = [.init(id: nil, keys: [.init(id: UUID().uuidString, publicKey: Data(count: 65))])]
    record.acceptedBatchIDs = [randomBytes(16)]
    record.inboundLastResort = .init(id: UUID().uuidString, publicKey: Data(count: 65))
    return record
}

/// Every field the meeting's save has no business with.
private struct Untouched: Equatable {
    let identifier, givenName, familyName, middleName, namePrefix, nameSuffix, nickname, note: String
    let organizationName, departmentName, jobTitle: String
    let birthday: String?
    let imageData, thumbnailImageData: Data?
    let visibleThroughDepth, globalTrusteeDepth, deletionToken, maxBundleVersion, signedAttributes: Data?
    let encryptionScheme: Int
    let phoneNumbers, emailAddresses, postalAddresses, urlAddresses: Int?

    @MainActor
    init(_ c: Contact.Profile) {
        (identifier, givenName, familyName, middleName) = (c.identifier, c.givenName, c.familyName, c.middleName)
        (namePrefix, nameSuffix, nickname, note) = (c.namePrefix, c.nameSuffix, c.nickname, c.note)
        (organizationName, departmentName, jobTitle, birthday) = (c.organizationName, c.departmentName, c.jobTitle, c.birthday)
        (imageData, thumbnailImageData) = (c.imageData, c.thumbnailImageData)
        (visibleThroughDepth, globalTrusteeDepth, deletionToken) = (c.visibleThroughDepth, c.globalTrusteeDepth, c.deletionToken)
        (maxBundleVersion, signedAttributes, encryptionScheme) = (c.maxBundleVersion, c.signedAttributes, c.encryptionScheme)
        (phoneNumbers, emailAddresses) = (c.phoneNumbers?.count, c.emailAddresses?.count)
        (postalAddresses, urlAddresses) = (c.postalAddresses?.count, c.urlAddresses?.count)
    }
}

@MainActor
private func expectCleared(_ record: PrekeyRecord, _ label: String) {
    #expect(record.ownBatches.isEmpty && record.inboundBatches.isEmpty, "\(label)")
    #expect(record.acceptedBatchIDs.isEmpty && record.inboundLastResort == nil, "\(label)")
}

@MainActor
@Suite("Meeting check — the save (update(key:for:)) without an Enclave", .serialized)
struct CardMeetingSaveTests {

    @Test("A contact whose field is already empty keeps its prekeys; an ordinary re-exchange is unchanged", .ambientTestKeyManager)
    func emptyFieldKeepsRecord() throws {
        let phone = try CardPhone()
        let id = try phone.newContact("Pat")
        let record = busyRecord()
        try phone.store(record, for: id)
        let field = try #require(try phone.rawField(id))

        try phone.run { try phone.cm.update(key: try inPersonKey(for: Data([1])), for: id) }

        #expect(try phone.record(id) == record, "an ordinary re-exchange keeps its prekeys")
        #expect(try phone.state(id) == .empty)
        #expect(try phone.rawField(id)?.count == field.count)
    }

    @Test("An issued card is cleared at the fixed length, and the batches go", .ambientTestKeyManager)
    func issuedCleared() throws {
        let phone = try CardPhone()
        let id = try phone.newContact("Pat")
        _ = try phone.run { try phone.cm.createCard(for: try phone.contact(id)) }
        try phone.store(busyRecord(), for: id)
        let before = try #require(try phone.rawField(id))
        let others = try phone.run { Untouched(try phone.contact(id)) }

        try phone.run { try phone.cm.update(key: try inPersonKey(for: Data([1])), for: id) }

        #expect(try phone.state(id) == .empty)
        #expect(try phone.rawField(id)?.count == before.count)
        #expect(try phone.rawField(id) != before)
        expectCleared(try phone.record(id), "issued")
        #expect(try phone.run { Untouched(try phone.contact(id)) } == others, "nothing else about the contact changes")
        #expect(try phone.run { try phone.cm.ownIssuedAgreementKeys() }.isEmpty, "the card is no longer one of ours")
    }

    @Test("The contact takes the keys: in-person owner hash makes it Verified", .ambientTestKeyManager)
    func takesKeysAndIsVerified() throws {
        let phone = try CardPhone()
        let id = try phone.newContact("Pat")
        _ = try phone.run { try phone.cm.createCard(for: try phone.contact(id)) }
        let ours = try phone.keyManager.retrieveIdentity()
        let keysBefore = try phone.run { try phone.contact(id).contactPublicKeys?.count }

        try phone.run { try phone.cm.update(key: try inPersonKey(for: ours), for: id) }

        #expect(try phone.run { try phone.contact(id).contactPublicKeys?.count } == (keysBefore ?? 0) + 1)
        #expect(try phone.run { try phone.contact(id).hasInPersonKeys })
        #expect(try phone.run { cardTier(of: try phone.contact(id)) } == .verified)
    }

    @Test("A second meeting leaves the record the first one's contact built", .ambientTestKeyManager)
    func secondMeetingKeepsRecord() throws {
        let phone = try CardPhone()
        let id = try phone.newContact("Pat")
        _ = try phone.run { try phone.cm.createCard(for: try phone.contact(id)) }
        try phone.run { try phone.cm.update(key: try inPersonKey(for: Data([1])), for: id) }
        let record = busyRecord()
        try phone.store(record, for: id)

        try phone.run { try phone.cm.update(key: try inPersonKey(for: Data([1])), for: id) }

        #expect(try phone.record(id) == record)
    }

    @Test("A card contact at a duress depth is cleared the same way", .ambientTestKeyManager)
    func hiddenContactCleared() throws {
        let phone = try CardPhone()
        let id = try phone.newContact("Pat")
        _ = try phone.run { try phone.cm.createCard(for: try phone.contact(id)) }
        try phone.store(busyRecord(), for: id)
        try phone.run {
            let contact = try phone.contact(id)
            contact.visibleThroughDepth = try DepthCodec.encode(0).encrypt()
            try phone.cm.modelContext.save()
            phone.cm.security.applyVerifyState(for: .duress)
        }

        try phone.run { try phone.cm.update(key: try inPersonKey(for: Data([1])), for: id) }

        #expect(try phone.state(id) == .empty)
        expectCleared(try phone.record(id), "hidden")
    }
}

@MainActor
@Suite("Meeting check — the save of a card conversation", .serialized, .enabled(if: enclave))
struct CardMeetingConversationSaveTests {

    @Test("Imported and conversation fields are cleared at the fixed length; the card-era batches go; nothing else changes",
          arguments: ["Carol imported, nothing sent", "Carol imported, sent", "Bob conversation", "Carol conversation"])
    func cleared(_ name: String) throws {
        let pair = try CardPhonePair()
        let phone: CardPhone, id: String
        switch name {
        case "Carol imported, nothing sent":
            (phone, id) = (pair.carol, pair.carolSide)
        case "Carol imported, sent":
            _ = try pair.carol.send(to: pair.carolSide)
            (phone, id) = (pair.carol, pair.carolSide)
        case "Bob conversation":
            _ = try pair.redeem()
            (phone, id) = (pair.bob, pair.bobSide)
        default:
            try pair.converse()
            (phone, id) = (pair.carol, pair.carolSide)
        }
        let before = try #require(try phone.rawField(id))
        let record = try phone.record(id)
        #expect(!record.ownBatches.isEmpty, "precondition: the flow made a batch")
        let others = try phone.run { Untouched(try phone.contact(id)) }

        try phone.run { try phone.cm.update(key: try inPersonKey(for: Data([1])), for: id) }

        #expect(try phone.state(id) == .empty, "\(name)")
        #expect(try phone.rawField(id)?.count == before.count, "\(name)")
        expectCleared(try phone.record(id), "\(name)")
        #expect(try phone.run { Untouched(try phone.contact(id)) } == others, "\(name): nothing else changes")
        #expect(try phone.run { try phone.cm.cardMeetingContext(for: try phone.contact(id)).sign } == nil, "no card key survives")
    }

    @Test("Both phones meet: the cards are gone, both contacts are Verified, and the old bundles no longer open")
    func bothMeet() throws {
        let pair = try CardPhonePair()
        try pair.converse()
        let stale = try pair.carol.send(to: pair.carolSide, "from before the meeting")

        for (phone, id) in [(pair.bob, pair.bobSide), (pair.carol, pair.carolSide)] {
            let ours = try phone.keyManager.retrieveIdentity()
            try phone.run { try phone.cm.update(key: try inPersonKey(for: ours), for: id) }
            #expect(try phone.state(id) == .empty)
            #expect(try phone.run { cardTier(of: try phone.contact(id)) } == .verified)
        }
        #expect(throws: (any Error).self) { try pair.bob.receive(stale) }
    }
}

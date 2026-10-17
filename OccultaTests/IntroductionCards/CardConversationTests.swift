//
//  CardConversationTests.swift
//  OccultaTests
//
//  ⚠️  Requires a Secure Enclave: Carol's pending prekey batch at import, and Bob's first batch at redemption, are
//  Enclave blobs made through `PrekeySecretsManager`. Everything else is software: the card keys are
//  `SoftwareCardKeys` and the ML-KEM key is `PostQuantumProviderFactory.createForTesting()`'s.
//
//  Introduction cards, stage C (`Docs/Features/Introduction Cards/SPEC.md` §3 to §6, §8): a card conversation end to
//  end. Bob and Carol are two devices, each with its own `Manager.Ambient` identity and its own store, as in
//  `PrekeyConversationTests`; bundles pass between them as `Data`. Which device is "this one" is the task-local,
//  bound per call by `CardPhone.run`, so a sealed field of one device is never opened with the other's local DB key.
//
//  The forged bundles are Carol's own bootstrap slot, built by hand from her stored state exactly as
//  `encryptCardBundle` builds it, with one thing wrong: `Forgery`.
//

import Testing
import Foundation
import CryptoKit
import SwiftData
import OccultaCore
@testable import Occulta
@testable import OccultaFormats

private func isUnrecognised(_ error: Error) -> Bool {
    if case ContactManager.Errors.noPublicKeyToEncryptWith = error { return true }
    return false
}

private func isHardBlocked(_ error: Error) -> Bool {
    if case ContactManager.CardError.hardBlocked = error { return true }
    return false
}

private func isIntroductionMismatch(_ error: Error) -> Bool {
    if case GroupDecryptError.cardIntroductionMismatch = error { return true }
    return false
}

/// What a device holds for a conversation, taken apart.
private struct Conversation {
    let agreementKey: Data
    let peerAgreementKey: Data
    let peerSigningKey: Data
    let quantum: QuantumKeyMaterial
    let bootstrapOpen: Bool
    let isIssuer: Bool

    init?(_ state: CardState) {
        guard case .conversation(let agreement, _, let peerAgreement, let peerSigning, let quantum, let open, let isIssuer) = state else {
            return nil
        }
        self.agreementKey = agreement
        self.peerAgreementKey = peerAgreement
        self.peerSigningKey = peerSigning
        self.quantum = quantum
        self.bootstrapOpen = open
        self.isIssuer = isIssuer
    }
}

// MARK: - Forging Carol's bootstrap bundle

/// What to get wrong in a bootstrap bundle that Carol's phone would never send.
private struct Forgery {
    /// Applied to Carol's introduction after it is signed.
    var introduction: (CardIntroduction) -> CardIntroduction = { $0 }
    /// The introduction is signed over this digest instead of the card's.
    var signOverDigest: Data?
    /// This key signs the slot's `senderEphemeralSignature`, not Carol's card signing key.
    var slotSigningBlob: Data?
    /// This stands in for Carol's agreement key in `senderFingerprint` and `senderProof`.
    var senderIdentity: Data?
    /// The shared payload; a basket by default.
    var sealed: OccultaBundle.SealedPayload?
}

private let noForgery = Forgery()

/// A bootstrap bundle from Carol to Bob built the way `encryptCardBundle` builds her imported branch, without
/// changing her stored state, and with `forgery` applied.
@MainActor
private func forgeBootstrap(from carol: CardPhone, to contactID: String, _ forgery: Forgery) throws -> Data {
    try carol.run {
        guard case .imported(let peerCard, let agreementBlob, let signingBlob, let mlkemBlob, let ss1, let ct1, _, _) =
                try carol.contact(contactID).cardState else {
            throw Forged.notImported
        }
        let peer = try #require(IntroductionCard.recognize(peerCard))
        let agreementKey = try carol.keys.agreementPublicKey(blob: agreementBlob)
        let signingKey = try carol.keys.signingPublicKey(blob: signingBlob)
        let mlkemKey = try #require(carol.pq.publicKey(forKeyBlob: mlkemBlob))
        let signature = try carol.keys.signDER(
            CardIntroduction.signingPayload(
                cardDigest: forgery.signOverDigest ?? peer.digest, agreementKey: agreementKey,
                signingKey: signingKey, mlkemEncapsulationKey: mlkemKey
            ),
            signingBlob: signingBlob
        )
        let introduction = forgery.introduction(CardIntroduction(
            agreementKey: agreementKey, signingKey: signingKey, mlkemEncapsulationKey: mlkemKey, signature: signature
        ))
        let slot = CardSlot(
            keys: carol.keys, agreementBlob: agreementBlob, signingBlob: forgery.slotSigningBlob ?? signingBlob,
            ownAgreementKey: agreementKey, bootstrap: .carol(ss1: ss1, ct1: ct1, introduction: introduction)
        )
        let sealed = try forgery.sealed ?? OccultaBundle.SealedPayload(
            message: WireHandle.encode(basket: CardPhone.basket("forged")), appVersion: Bundle.main.appVersion
        )
        let bundle = try Manager.Crypto().seal(
            sealedPayload: sealed,
            groupID: UUID(),
            recipients: [GroupRecipient(
                publicKey: peer.agreementKey, quantumMaterial: nil, contactPrekey: nil, pendingBatch: nil,
                prefixesEphemeralSignature: true, card: slot
            )],
            senderIdentity: forgery.senderIdentity ?? agreementKey
        )
        return try bundle.encoded(version: .v4)
    }
}

private enum Forged: Error { case notImported }

/// `bundle` with one thing changed on the wire.
private func tampered(_ data: Data, _ kind: String) throws -> Data {
    let bundle = try OccultaBundle.decoded(from: data)
    let envelope = try #require(bundle.group)
    func flipped(_ bytes: Data) -> Data { var copy = bytes; copy[copy.startIndex + copy.count / 2] ^= 0x01; return copy }

    var ciphertext = bundle.ciphertext, fingerprint = bundle.senderFingerprint, nonce = bundle.fingerprintNonce
    var blind = envelope.blind
    var recipients = envelope.recipients
    let slot = try #require(recipients.first)
    switch kind {
    case "body":        ciphertext = flipped(ciphertext)
    case "slot":        recipients[0] = .init(secrecyContext: slot.secrecyContext, wrappedPayload: flipped(slot.wrappedPayload))
    case "slotHeader":  recipients[0] = .init(secrecyContext: slot.secrecyContext, wrappedPayload: Data(slot.wrappedPayload.prefix(8)) + flipped(Data(slot.wrappedPayload.dropFirst(8))))
    case "ephemeral":
        var ephemeral = slot.secrecyContext.ephemeralPublicKey
        ephemeral[ephemeral.startIndex + 40] ^= 0x01
        recipients[0] = .init(
            secrecyContext: .init(mode: slot.secrecyContext.mode, ephemeralPublicKey: ephemeral, prekeyID: slot.secrecyContext.prekeyID),
            wrappedPayload: slot.wrappedPayload
        )
    case "fingerprint": fingerprint = flipped(fingerprint)
    case "nonce":       nonce = flipped(nonce)
    case "blind":       blind = flipped(blind)
    default:            Issue.record("unknown tamper \(kind)")
    }
    return try OccultaBundle(
        version: bundle.version, secrecy: bundle.secrecy, ciphertext: ciphertext, fingerprintNonce: nonce,
        senderFingerprint: fingerprint,
        group: .init(version: envelope.version, blind: blind, blindNonce: envelope.blindNonce, recipients: recipients)
    ).encoded(version: .v4)
}

private let enclave = TestSupport.secureEnclaveAvailable()

// MARK: - 1, 2, 3: the conversation

@MainActor
@Suite("Card conversation — Bob issues, Carol answers (SPEC §3 to §6)", .serialized, .enabled(if: enclave))
struct CardConversationTests {

    @Test("Happy path: Bob opens the second message first, then the first; Bob replies; Carol's next ends the bootstrap")
    func happyPath() throws {
        let pair = try CardPhonePair()
        let (bob, carol, bobSide, carolSide) = (pair.bob, pair.carol, pair.bobSide, pair.carolSide)

        guard case .imported(_, _, _, _, let ss1, let ct1, _, _) = try carol.state(carolSide) else { Issue.record("precondition"); return }
        let first = try carol.send(to: carolSide, "first")
        let second = try carol.send(to: carolSide, "second")
        guard case .imported(_, _, _, _, _, _, _, let sent) = try carol.state(carolSide) else { Issue.record("still imported"); return }
        #expect(sent, "sentFirstMessage after Carol's send")

        // Bob opens #2 first: it redeems.
        guard case .issued = try bob.state(bobSide) else { Issue.record("precondition: issued"); return }
        let openedSecond = try bob.receive(second)
        #expect(openedSecond.ownerID == bobSide)
        #expect(openedSecond.text == "second")

        let afterRedemption = try #require(Conversation(try bob.state(bobSide)))
        #expect(afterRedemption.bootstrapOpen)
        let bobQuantum = afterRedemption.quantum
        #expect(bobQuantum.isValid)
        #expect(bobQuantum.decapsulatedSecret == ss1, "what Bob decapsulated is Carol's ss1")
        #expect(bobQuantum.peerCiphertext == ct1)
        #expect(bobQuantum.encapsulatedSecret != ss1)
        #expect(afterRedemption.isIssuer, "Bob's field says he issued the card")
        #expect(try bob.hasPendingBatch(bobSide), "Bob made his first batch for Carol")
        #expect(try bob.heldKeyCount(bobSide) == Manager.PrekeySecretsManager.defaultBatchSize, "and accepted Carol's")

        // Then #1, as a known card sender.
        let openedFirst = try bob.receive(first)
        #expect(openedFirst.ownerID == bobSide)
        #expect(openedFirst.text == "first")
        let afterBoth = try #require(Conversation(try bob.state(bobSide)))
        #expect(afterBoth.bootstrapOpen, "bootstrap messages don't close the bootstrap")
        #expect(afterBoth.quantum == bobQuantum, "the second message doesn't redeem again")
        #expect(try bob.heldKeyCount(bobSide) == Manager.PrekeySecretsManager.defaultBatchSize, "the repeated batch isn't accepted twice")
        #expect(try bob.record(bobSide).inboundBatches.count == 1)

        // Bob replies; Carol opens it.
        let reply = try bob.send(to: bobSide, "reply")
        #expect(try bob.heldKeyCount(bobSide) == Manager.PrekeySecretsManager.defaultBatchSize - 1, "Bob used one of Carol's keys")
        #expect(try carol.run { carol.cm.cardSecrecyIsStandard(for: try carol.contact(carolSide)) }, "still imported")
        let openedReply = try carol.receive(reply)
        #expect(openedReply.ownerID == carolSide)
        #expect(openedReply.text == "reply")

        let carolConversation = try #require(Conversation(try carol.state(carolSide)))
        #expect(!carolConversation.bootstrapOpen)
        #expect(!carolConversation.isIssuer)
        let carolQuantum = carolConversation.quantum
        #expect(carolQuantum.isValid)
        #expect(carolQuantum.encapsulatedSecret == ss1 && carolQuantum.decapsulatedSecret == bobQuantum.encapsulatedSecret,
                "the same two secrets, held the other way round")
        #expect(carolQuantum.ourCiphertext == bobQuantum.peerCiphertext && carolQuantum.peerCiphertext == bobQuantum.ourCiphertext)
        #expect(carolConversation.peerAgreementKey == pair.card.agreementKey)
        #expect(carolConversation.peerSigningKey == pair.card.signingKey)
        #expect(carolConversation.agreementKey.isEmpty == false)
        #expect(afterBoth.peerAgreementKey == (try carol.run { try carol.keys.agreementPublicKey(blob: carolConversationAgreementBlob(carol, carolSide)) }))

        // Carol's reply proof: Bob's batch arrived, the key Bob used from hers is gone, her batch is delivered.
        #expect(try carol.heldKeyCount(carolSide) == Manager.PrekeySecretsManager.defaultBatchSize)
        #expect(try carol.ownKeyCount(carolSide) == Manager.PrekeySecretsManager.defaultBatchSize - 1, "her batch, minus the one key Bob used")
        #expect(try carol.hasPendingBatch(carolSide) == false)

        // Carol's next message is an ordinary slot, and ends Bob's bootstrap.
        let heldBefore = try carol.heldKeyCount(carolSide)
        let ownBefore = try bob.ownKeyCount(bobSide)
        let next = try carol.send(to: carolSide, "ordinary")
        #expect(try carol.heldKeyCount(carolSide) == heldBefore - 1, "an ordinary slot goes to one of Bob's keys")
        #expect(try bob.receive(next).text == "ordinary")
        #expect(try #require(Conversation(try bob.state(bobSide))).bootstrapOpen == false)
        #expect(try bob.ownKeyCount(bobSide) == ownBefore - 1, "Bob's key was consumed on opening")
        #expect(try bob.hasPendingBatch(bobSide) == false, "Carol's use of a key proves Bob's batch arrived")

        // Bob's next is ordinary too (no bootstrap), and several more each way open.
        for round in 0..<6 {
            #expect(try carol.receive(try bob.send(to: bobSide, "b\(round)")).text == "b\(round)")
            #expect(try bob.receive(try carol.send(to: carolSide, "c\(round)")).text == "c\(round)")
        }
        #expect(try bob.run { bob.cm.cardSecrecyIsStandard(for: try bob.contact(bobSide)) } == false)
        #expect(try carol.run { carol.cm.cardSecrecyIsStandard(for: try carol.contact(carolSide)) } == false)
        #expect(Conversation(try bob.state(bobSide))?.quantum == bobQuantum, "the material doesn't change")
    }

    private func carolConversationAgreementBlob(_ carol: CardPhone, _ id: String) throws -> Data {
        guard case .conversation(let blob, _, _, _, _, _, _) = try carol.contact(id).cardState else { throw Forged.notImported }
        return blob
    }

    @Test("Bob's first reply is a bootstrap slot; the bootstrap slots carry no marker the ordinary ones lack")
    func bootstrapSlotsLookOrdinary() throws {
        let pair = try CardPhonePair()
        let (first, _) = try pair.redeem()
        let reply = try pair.bob.send(to: pair.bobSide, "reply")
        try pair.bob.receive(first)

        for data in [first, reply] {
            let bundle = try OccultaBundle.decoded(from: data)
            let slot = try #require(bundle.group?.recipients.first)
            #expect(slot.secrecyContext.mode == .forwardSecret)
            #expect(slot.secrecyContext.ephemeralPublicKey.count == 65)
            #expect(UUID(uuidString: try #require(slot.secrecyContext.prekeyID)) != nil)
            #expect(bundle.group?.recipients.count == 1)
        }
    }

    @Test("The bundles are routed and signed under the card keys, never the identity key")
    func cardKeysNotIdentityKeys() throws {
        let pair = try CardPhonePair()
        let (first, _) = try pair.redeem()
        try pair.bob.receive(first)
        let reply = try pair.bob.send(to: pair.bobSide, "reply")

        let carolAgreement = try pair.carol.run {
            guard case .imported(_, let blob, _, _, _, _, _, _) = try pair.carol.contact(pair.carolSide).cardState else { throw Forged.notImported }
            return try pair.carol.keys.agreementPublicKey(blob: blob)
        }
        let bundle = try OccultaBundle.decoded(from: first)
        let carolIdentity = try pair.carol.keyManager.retrieveIdentity()
        #expect(bundle.senderFingerprint == OccultaBundle.SecrecyContext.fingerprint(for: carolAgreement, nonce: bundle.fingerprintNonce))
        #expect(bundle.senderFingerprint != OccultaBundle.SecrecyContext.fingerprint(for: carolIdentity, nonce: bundle.fingerprintNonce))

        let replyBundle = try OccultaBundle.decoded(from: reply)
        let bobIdentity = try pair.bob.keyManager.retrieveIdentity()
        #expect(replyBundle.senderFingerprint == OccultaBundle.SecrecyContext.fingerprint(for: pair.card.agreementKey, nonce: replyBundle.fingerprintNonce))
        #expect(replyBundle.senderFingerprint != OccultaBundle.SecrecyContext.fingerprint(for: bobIdentity, nonce: replyBundle.fingerprintNonce))
    }

    // MARK: Labels and helpers (2)

    @Test("Standard Encryption holds for Carol while imported, and not after Bob's reply")
    func secrecyLabel() throws {
        let pair = try CardPhonePair()
        let carol = pair.carol
        #expect(try carol.run { carol.cm.cardSecrecyIsStandard(for: try carol.contact(pair.carolSide)) })
        try pair.converse()
        #expect(try carol.run { carol.cm.cardSecrecyIsStandard(for: try carol.contact(pair.carolSide)) } == false)
        #expect(try pair.bob.run { pair.bob.cm.cardSecrecyIsStandard(for: try pair.bob.contact(pair.bobSide)) } == false)
    }

    @Test("Carol can't send past the expiry before she has sent, and can after she has")
    func canSend() throws {
        let bob = try CardPhone(), carol = try CardPhone()
        let bobSide = try bob.newContact("Carol"), carolSide = try carol.newContact("Bob")
        // A card that expired an hour ago, issued and imported back then.
        let issuedAt = Date.now.addingTimeInterval(-25 * 3_600)
        let card = try bob.run { try bob.cm.createCard(for: try bob.contact(bobSide), now: issuedAt) }
        try carol.run { try carol.cm.importCard(card.encoded, into: try carol.contact(carolSide), newContactName: nil, now: issuedAt) }
        #expect(card.expiresAt < .now, "precondition")

        #expect(try carol.run { carol.cm.canSendToCardContact(try carol.contact(carolSide)) } == false)
        let before = try carol.rawField(carolSide)
        #expect {
            try carol.send(to: carolSide)
        } throws: { error in
            if case ContactManager.CardError.cannotSend = error { return true }
            return false
        }
        #expect(try carol.rawField(carolSide) == before, "a refused send changes nothing")

        // The same card, once she has sent: she may keep sending.
        guard case .imported(let peerCard, let agreement, let signing, let mlkem, let ss1, let ct1, let expiresAt, _) = try carol.state(carolSide) else {
            Issue.record("precondition"); return
        }
        try carol.run {
            try carol.cm.store(
                .imported(peerCard: peerCard, agreementKey: agreement, signingKey: signing, mlkemKey: mlkem, ss1: ss1, ct1: ct1,
                          expiresAt: expiresAt, sentFirstMessage: true),
                for: try carol.contact(carolSide)
            )
        }
        #expect(try carol.run { carol.cm.canSendToCardContact(try carol.contact(carolSide)) })
        _ = try carol.send(to: carolSide, "late follow-up")
    }

    @Test("A fresh imported card can send, and an issued or empty contact can't")
    func canSendStates() throws {
        let pair = try CardPhonePair()
        #expect(try pair.carol.run { pair.carol.cm.canSendToCardContact(try pair.carol.contact(pair.carolSide)) })
        #expect(try pair.bob.run { pair.bob.cm.canSendToCardContact(try pair.bob.contact(pair.bobSide)) } == false, "issued")
        let other = try pair.bob.newContact("Plain")
        #expect(try pair.bob.run { pair.bob.cm.canSendToCardContact(try pair.bob.contact(other)) } == false, "empty")
    }

    // MARK: 3

    @Test("sentFirstMessage is saved when the first bundle is built, readable from a fresh context")
    func sentFlagSaved() throws {
        let pair = try CardPhonePair()
        let carol = pair.carol
        guard case .imported(_, _, _, _, _, _, _, let before) = try carol.state(pair.carolSide) else { Issue.record("precondition"); return }
        #expect(before == false)

        _ = try carol.send(to: pair.carolSide)

        let reread = try carol.run {
            try ModelContext(carol.container).fetch(FetchDescriptor<Contact.Profile>())
                .first { $0.identifier == pair.carolSide }?.cardState
        }
        guard case .imported(_, _, _, _, _, _, _, let after)? = reread else { Issue.record("should be imported"); return }
        #expect(after, "a bundle that may have left must never leave the card open to the sweep")

        // So the sweep keeps it past the deadline.
        try carol.run { try carol.cm.sweepCards(now: pair.card.expiresAt.addingTimeInterval(1)) }
        guard case .imported = try carol.state(pair.carolSide) else { Issue.record("swept after sending"); return }
    }

    @Test("A second message doesn't change what the first set")
    func secondSendKeepsState() throws {
        let pair = try CardPhonePair()
        _ = try pair.carol.send(to: pair.carolSide)
        let afterFirst = try pair.carol.state(pair.carolSide)
        _ = try pair.carol.send(to: pair.carolSide)
        #expect(try pair.carol.state(pair.carolSide) == afterFirst)
    }

    // MARK: 5

    @Test("A contact hidden at a duress depth redeems and converses exactly as at depth 0")
    func duress() throws {
        let plain = try CardPhonePair()
        let hidden = try CardPhonePair(hiddenAtDuressDepth: true)

        for pair in [plain, hidden] { try pair.converse() }

        let plainState = try #require(Conversation(try plain.bob.state(plain.bobSide)))
        let hiddenState = try #require(Conversation(try hidden.bob.state(hidden.bobSide)))
        #expect(plainState.bootstrapOpen == hiddenState.bootstrapOpen)
        #expect(plainState.quantum.isValid && hiddenState.quantum.isValid)
        #expect(plainState.isIssuer && hiddenState.isIssuer)
        #expect(try plain.bob.rawField(plain.bobSide)?.count == hidden.bob.rawField(hidden.bobSide)?.count, "one sealed length")
        #expect(try plain.bob.heldKeyCount(plain.bobSide) == hidden.bob.heldKeyCount(hidden.bobSide))

        // And on: both go on conversing.
        for pair in [plain, hidden] {
            #expect(try pair.bob.receive(try pair.carol.send(to: pair.carolSide, "more")).text == "more")
            #expect(try pair.carol.receive(try pair.bob.send(to: pair.bobSide, "back")).text == "back")
        }
    }

    @Test("A hidden contact's expired card is cancelled at receipt, as at depth 0")
    func duressExpiry() throws {
        let pair = try CardPhonePair(hiddenAtDuressDepth: true)
        let bundle = try OccultaBundle.decoded(from: try pair.carol.send(to: pair.carolSide))
        let redeemed = try pair.bob.run { try pair.bob.cm.redeemCard(for: bundle, now: pair.card.expiresAt) }
        #expect(redeemed == nil)
        #expect(try pair.bob.state(pair.bobSide) == .empty)
    }

    // MARK: 8

    @Test("Bob discards: empty field, batches cleared, Carol's next bundle is unrecognised")
    func discard() throws {
        let pair = try CardPhonePair()
        try pair.converse()
        let (bob, carol) = (pair.bob, pair.carol)
        let lengthBefore = try bob.rawField(pair.bobSide)?.count
        #expect(try bob.ownKeyCount(pair.bobSide) > 0 && bob.heldKeyCount(pair.bobSide) > 0, "precondition: batches exist")

        try bob.run { try bob.cm.discardCardConversation(for: try bob.contact(pair.bobSide)) }

        #expect(try bob.state(pair.bobSide) == .empty)
        #expect(try bob.rawField(pair.bobSide)?.count == lengthBefore)
        let record = try bob.record(pair.bobSide)
        #expect(record.ownBatches.isEmpty && record.inboundBatches.isEmpty && record.acceptedBatchIDs.isEmpty)
        #expect(record.inboundLastResort == nil)

        let next = try carol.send(to: pair.carolSide, "still here")
        #expect { try bob.receive(next) } throws: { isUnrecognised($0) }
        #expect(try bob.state(pair.bobSide) == .empty, "an unrecognised bundle doesn't revive the card")
        #expect(try bob.cm.fetchAllContactsCount(in: bob) == 1, "and creates no contact")
    }

    @Test("Bob discards before Carol has heard back: her bootstrap bundle is unrecognised")
    func discardBeforeReply() throws {
        let pair = try CardPhonePair()
        let (first, second) = try pair.redeem()
        try pair.bob.run { try pair.bob.cm.discardCardConversation(for: try pair.bob.contact(pair.bobSide)) }

        #expect { try pair.bob.receive(first) } throws: { isUnrecognised($0) }
        #expect { try pair.bob.receive(second) } throws: { isUnrecognised($0) }
        #expect(try pair.bob.state(pair.bobSide) == .empty)
    }

    @Test("Discarding needs a conversation")
    func discardNeedsConversation() throws {
        let pair = try CardPhonePair()
        #expect {
            try pair.bob.run { try pair.bob.cm.discardCardConversation(for: try pair.bob.contact(pair.bobSide)) }
        } throws: { error in
            if case ContactManager.CardError.noCardConversation = error { return true }
            return false
        }
        guard case .issued = try pair.bob.state(pair.bobSide) else { Issue.record("an issued card is untouched"); return }
    }
}

// MARK: - 4: rejections

@MainActor
@Suite("Card conversation — what Bob refuses (SPEC §6.6)", .serialized, .enabled(if: enclave))
struct CardRedemptionRejectionTests {

    @Test("Two senders on copies of one card: whichever Bob opens first wins, the other is unrecognised", arguments: [false, true])
    func twoSenders(daveFirst: Bool) throws {
        let pair = try CardPhonePair()
        let (bob, carol) = (pair.bob, pair.carol)
        let dave = try CardPhone()
        let daveSide = try dave.newContact("Bob")
        try dave.run { try dave.cm.importCard(pair.card.encoded, into: try dave.contact(daveSide), newContactName: nil) }

        let fromCarol = try carol.send(to: pair.carolSide, "carol")
        let fromDave = try dave.send(to: daveSide, "dave")
        let (winner, loser) = daveFirst ? (fromDave, fromCarol) : (fromCarol, fromDave)

        #expect(try bob.receive(winner).ownerID == pair.bobSide)
        let stateAfterWinner = try bob.state(pair.bobSide)
        let recordAfterWinner = try bob.record(pair.bobSide)

        #expect { try bob.receive(loser) } throws: { isUnrecognised($0) }
        #expect(try bob.state(pair.bobSide) == stateAfterWinner, "the loser changed nothing")
        #expect(try bob.record(pair.bobSide) == recordAfterWinner)

        let winnerDevice = daveFirst ? dave : carol
        let winnerSide = daveFirst ? daveSide : pair.carolSide
        let winnerAgreement = try winnerDevice.run {
            guard case .imported(_, let blob, _, _, _, _, _, _) = try winnerDevice.contact(winnerSide).cardState else { throw Forged.notImported }
            return try winnerDevice.keys.agreementPublicKey(blob: blob)
        }
        #expect(try #require(Conversation(stateAfterWinner)).peerAgreementKey == winnerAgreement)

        // The winner goes on; the loser's earlier bundles stay unrecognised.
        #expect(try bob.receive(try winnerDevice.send(to: winnerSide, "again")).text == "again")
        #expect { try bob.receive(loser) } throws: { isUnrecognised($0) }
    }

    @Test("Redemption after the expiry fails and the card is cancelled")
    func expired() throws {
        let pair = try CardPhonePair()
        let bundle = try OccultaBundle.decoded(from: try pair.carol.send(to: pair.carolSide))
        let before = try pair.bob.record(pair.bobSide)

        let redeemed = try pair.bob.run { try pair.bob.cm.redeemCard(for: bundle, now: pair.card.expiresAt) }

        #expect(redeemed == nil, "the deadline is when Bob opens it, with no grace")
        #expect(try pair.bob.state(pair.bobSide) == .empty)
        #expect(try pair.bob.record(pair.bobSide) == before, "nothing generated")
        #expect(try pair.bob.run { try pair.bob.cm.ownIssuedAgreementKeys() }.isEmpty)
    }

    @Test("Redemption one second before the expiry still works")
    func lastSecond() throws {
        let pair = try CardPhonePair()
        let bundle = try OccultaBundle.decoded(from: try pair.carol.send(to: pair.carolSide))
        let redeemed = try pair.bob.run { try pair.bob.cm.redeemCard(for: bundle, now: pair.card.expiresAt.addingTimeInterval(-1)) }
        #expect(redeemed != nil)
        guard case .conversation = try pair.bob.state(pair.bobSide) else { Issue.record("should be a conversation"); return }
    }

    @Test("A bundle tampered with on the wire leaves the card issued and generates nothing",
          arguments: ["body", "slot", "slotHeader", "ephemeral", "fingerprint", "nonce", "blind"])
    func tamperedWire(_ kind: String) throws {
        let pair = try CardPhonePair()
        let bad = try tampered(try pair.carol.send(to: pair.carolSide), kind)
        let field = try pair.bob.rawField(pair.bobSide)
        let record = try pair.bob.record(pair.bobSide)

        #expect { try pair.bob.receive(bad) } throws: { _ in true }

        #expect(try pair.bob.rawField(pair.bobSide) == field, "\(kind): the card is untouched, byte for byte")
        #expect(try pair.bob.record(pair.bobSide) == record, "\(kind): no batch generated, no key consumed")
        guard case .issued = try pair.bob.state(pair.bobSide) else { Issue.record("\(kind): should still be issued"); return }
    }

    @Test("The untampered bundle redeems, so the failures above are the tampering's")
    func untamperedControl() throws {
        let pair = try CardPhonePair()
        let good = try pair.carol.send(to: pair.carolSide)
        #expect(try pair.bob.receive(good).ownerID == pair.bobSide)
    }

    @Test("A hand-built bundle with nothing wrong with it redeems: the forging helper is faithful")
    func forgeryControl() throws {
        let pair = try CardPhonePair()
        let bundle = try forgeBootstrap(from: pair.carol, to: pair.carolSide, noForgery)
        #expect(try pair.bob.receive(bundle).text == "forged")
        guard case .conversation = try pair.bob.state(pair.bobSide) else { Issue.record("should be a conversation"); return }
    }

    @Test("Each check on the bootstrap slot refuses, in turn, leaving the card issued and generating nothing",
          arguments: ["introductionSignature", "introductionKey", "otherCardDigest", "slotSignature", "fingerprint", "identityChallenge"])
    func forged(_ kind: String) throws {
        let pair = try CardPhonePair()
        var forgery = Forgery()
        switch kind {
        case "introductionSignature":
            forgery.introduction = { intro in
                var signature = intro.signature
                signature[signature.endIndex - 3] ^= 0x01
                return CardIntroduction(agreementKey: intro.agreementKey, signingKey: intro.signingKey,
                                        mlkemEncapsulationKey: intro.mlkemEncapsulationKey, signature: signature)
            }
        case "introductionKey":
            // Keys swapped after signing: the signature no longer covers them.
            forgery.introduction = { intro in
                CardIntroduction(agreementKey: intro.agreementKey, signingKey: intro.signingKey,
                                 mlkemEncapsulationKey: Data(intro.mlkemEncapsulationKey.reversed()), signature: intro.signature)
            }
        case "otherCardDigest":
            // Valid for another card: a replay against this one.
            forgery.signOverDigest = Data(SHA256.hash(data: Data("another card".utf8)))
        case "slotSignature":
            forgery.slotSigningBlob = try pair.carol.keys.makeSigningKey().blob
        case "fingerprint":
            forgery.senderIdentity = Data([0x04]) + randomBytes(64)
        case "identityChallenge":
            forgery.sealed = .init(
                message: try WireHandle.encode(basket: CardPhone.basket("x")),
                identityChallenge: IdentityChallengeEnvelope(kind: .challenge, payload: Data(count: 72), contextNote: nil),
                appVersion: Bundle.main.appVersion
            )
        default:
            Issue.record("unknown forgery \(kind)")
        }
        let bundle = try forgeBootstrap(from: pair.carol, to: pair.carolSide, forgery)
        let field = try pair.bob.rawField(pair.bobSide)
        let record = try pair.bob.record(pair.bobSide)

        #expect { try pair.bob.receive(bundle) } throws: { isUnrecognised($0) }

        #expect(try pair.bob.rawField(pair.bobSide) == field, "\(kind)")
        #expect(try pair.bob.record(pair.bobSide) == record, "\(kind)")
    }
}

// MARK: - Introduction check (unit)

@MainActor
@Suite("Card conversation — Bob's check of a repeated introduction (SPEC §4.4, §6.6)", .serialized)
struct CardIntroductionCheckTests {

    private func introduction(agreement: UInt8 = 1, signature: UInt8 = 9) -> CardIntroduction {
        CardIntroduction(
            agreementKey: Data([0x04]) + Data(repeating: agreement, count: 64), signingKey: Data([0x04]) + Data(repeating: 2, count: 64),
            mlkemEncapsulationKey: Data(repeating: 3, count: 1_568), signature: Data(repeating: signature, count: 71)
        )
    }

    private func opening(_ introduction: CardIntroduction?, wasBootstrap: Bool) -> CardSlotOpening {
        CardSlotOpening(
            payload: OccultaBundle.RecipientPayload(sessionKey: Data(count: 32), introduction: introduction),
            used: .longTerm, mode: .forwardSecret, ephemeralPublicKey: Data(count: 65),
            wasBootstrap: wasBootstrap, derivedQuantum: nil
        )
    }

    /// Bob's contact (`isIssuer`) or Carol's, holding `stored`'s agreement and signing keys as the peer's. Runs under
    /// an ambient test key only.
    private func contact(peer stored: CardIntroduction, isIssuer: Bool, in cm: ContactManager) throws -> Contact.Profile {
        let profile = Contact.Profile(
            identifier: UUID().uuidString, givenName: "", familyName: "", middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        try cm.insertProfile(profile)
        try cm.store(
            .conversation(
                agreementKey: randomBytes(143), signingKey: randomBytes(143),
                peerAgreementKey: stored.agreementKey, peerSigningKey: stored.signingKey,
                quantum: cardTestQuantum(), bootstrapOpen: true, isIssuer: isIssuer
            ),
            for: profile
        )
        return profile
    }

    @Test("The same keys with a fresh signature are accepted", .ambientTestKeyManager)
    func sameKeysFreshSignature() throws {
        let cm = try CardPhone().cm
        let contact = try self.contact(peer: self.introduction(signature: 9), isIssuer: true, in: cm)
        try cm.checkCardIntroduction(self.opening(self.introduction(signature: 7), wasBootstrap: true), for: contact)
    }

    @Test("A different agreement or signing key is a mismatch", .ambientTestKeyManager, arguments: ["agreement", "signing"])
    func differentKeys(_ which: String) throws {
        let cm = try CardPhone().cm
        let stored = self.introduction()
        let contact = try self.contact(peer: stored, isIssuer: true, in: cm)
        let changed: CardIntroduction
        switch which {
        case "agreement":
            changed = CardIntroduction(agreementKey: self.introduction(agreement: 5).agreementKey, signingKey: stored.signingKey,
                                       mlkemEncapsulationKey: stored.mlkemEncapsulationKey, signature: stored.signature)
        case "signing":
            changed = CardIntroduction(agreementKey: stored.agreementKey, signingKey: Data([0x04]) + Data(repeating: 6, count: 64),
                                       mlkemEncapsulationKey: stored.mlkemEncapsulationKey, signature: stored.signature)
        default:
            Issue.record("unknown change \(which)")
            return
        }
        #expect { try cm.checkCardIntroduction(self.opening(changed, wasBootstrap: true), for: contact) } throws: { isIntroductionMismatch($0) }
        #expect { try cm.checkCardIntroduction(self.opening(changed, wasBootstrap: false), for: contact) } throws: { isIntroductionMismatch($0) }
    }

    /// Bob compares the agreement and signing keys only. The slot's own signature, verified under the stored
    /// `peerSigningKey` before this check runs, already binds Carol's signing key to the message, and after redemption
    /// Bob never uses her ML-KEM key (`ss2` was encapsulated to it once, at redemption), so a different one changes
    /// nothing he relies on. Comparing it would only reject a message the slot's signature has authenticated.
    @Test("A different ML-KEM key in the introduction passes: Bob never uses it after redemption", .ambientTestKeyManager)
    func differentMLKEMKeyPasses() throws {
        let cm = try CardPhone().cm
        let stored = self.introduction()
        let contact = try self.contact(peer: stored, isIssuer: true, in: cm)
        let changed = CardIntroduction(
            agreementKey: stored.agreementKey, signingKey: stored.signingKey,
            mlkemEncapsulationKey: Data(repeating: 4, count: 1_568), signature: stored.signature
        )
        try cm.checkCardIntroduction(self.opening(changed, wasBootstrap: true), for: contact)
        try cm.checkCardIntroduction(self.opening(changed, wasBootstrap: false), for: contact)
    }

    @Test("A bootstrap slot without an introduction is a mismatch; an ordinary one without is fine", .ambientTestKeyManager)
    func missingIntroduction() throws {
        let cm = try CardPhone().cm
        let contact = try self.contact(peer: self.introduction(), isIssuer: true, in: cm)
        #expect { try cm.checkCardIntroduction(self.opening(nil, wasBootstrap: true), for: contact) } throws: { isIntroductionMismatch($0) }
        try cm.checkCardIntroduction(self.opening(nil, wasBootstrap: false), for: contact)
    }

    @Test("Carol's side, which never checks an introduction, checks nothing", .ambientTestKeyManager)
    func carolChecksNothing() throws {
        let cm = try CardPhone().cm
        let contact = try self.contact(peer: self.introduction(), isIssuer: false, in: cm)
        try cm.checkCardIntroduction(self.opening(self.introduction(), wasBootstrap: true), for: contact)
        try cm.checkCardIntroduction(self.opening(nil, wasBootstrap: true), for: contact)
    }
}

// MARK: - 6: hard blocks

@MainActor
@Suite("Card conversation — the hard blocks (SPEC §8)", .serialized, .enabled(if: enclave))
struct CardHardBlockTests {

    @Test("A group send that includes a card contact throws, on either side")
    func groupSend() throws {
        let pair = try CardPhonePair()
        try pair.converse()
        for (device, side) in [(pair.bob, pair.bobSide), (pair.carol, pair.carolSide)] {
            try device.run {
                let group = try device.cm.createGroup(name: "G")
                try group.addMember(side, atDepth: 0)
                #expect { try device.cm.encryptGroupBundle(basket: CardPhone.basket("x"), groupID: try #require(group.readID())) }
                    throws: { isHardBlocked($0) }
            }
        }
    }

    @Test("A group send that includes a card contact still imported (Carol, before the reply) throws")
    func groupSendImported() throws {
        let pair = try CardPhonePair()
        try pair.carol.run {
            let group = try pair.carol.cm.createGroup(name: "G")
            try group.addMember(pair.carolSide, atDepth: 0)
            #expect { try pair.carol.cm.encryptGroupBundle(basket: CardPhone.basket("x"), groupID: try #require(group.readID())) }
                throws: { isHardBlocked($0) }
        }
    }

    @Test("Group eligibility refuses a card contact, by reason cardConversation")
    func groupEligibility() throws {
        let pair = try CardPhonePair()
        try pair.converse()
        let (eligible, reason) = try pair.carol.run {
            (try pair.carol.cm.isGroupEligible(identifier: pair.carolSide), try pair.carol.cm.groupIneligibilityReason(for: pair.carolSide))
        }
        #expect(eligible == false)
        #expect(reason == .cardConversation)
        // An issued card is not yet a card conversation.
        let issuedSide = try pair.bob.newContact("Issued")
        try pair.bob.run { try pair.bob.cm.createCard(for: try pair.bob.contact(issuedSide)) }
        let issuedReason = try pair.bob.run { try pair.bob.cm.groupIneligibilityReason(for: issuedSide) }
        #expect(issuedReason != .cardConversation)
    }

    @Test("Sending shard operations, a custody manifest or an identity challenge to a card contact throws; nothing changes")
    func shardAndChallengeSend() throws {
        let pair = try CardPhonePair()
        try pair.converse()
        for (device, side) in [(pair.bob, pair.bobSide), (pair.carol, pair.carolSide)] {
            let field = try device.rawField(side)
            let record = try device.record(side)
            try device.run {
                #expect { try device.cm.encryptBundle(basket: nil, for: side, shardOperations: [.init(kind: .handback)]) }
                    throws: { isHardBlocked($0) }
                #expect { try device.cm.encryptBundle(basket: nil, for: side, custodyManifest: [UUID()]) }
                    throws: { isHardBlocked($0) }
                #expect {
                    try device.cm.encryptBundle(
                        basket: nil, for: side,
                        identityChallenge: IdentityChallengeEnvelope(kind: .challenge, payload: Data(count: 72), contextNote: nil)
                    )
                } throws: { isHardBlocked($0) }
                #expect { try device.cm.encryptBundle(basket: CardPhone.basket("x"), for: side, shardOperations: [.init(kind: .handback)]) }
                    throws: { isHardBlocked($0) }
            }
            #expect(try device.rawField(side) == field && device.record(side) == record, "a refused send consumes no key")
        }
    }

    @Test("Compose's send, with an empty shard list and an empty custody manifest, goes through and carries neither")
    func composeShapedSend() throws {
        let pair = try CardPhonePair()
        // What `ComposeViewModel` passes for every contact: the manifest is `[]`, not nil (found in the Simulator).
        let first = try pair.carol.run {
            try pair.carol.cm.encryptBundle(basket: CardPhone.basket("first"), for: pair.carolSide, shardOperations: nil, custodyManifest: [])
        }
        let opened = try pair.bob.run { try pair.bob.cm.openGroup(bundle: try OccultaBundle.decoded(from: first)) }

        #expect(opened.ownerID == pair.bobSide)
        #expect(opened.sealed.custodyManifest == nil || opened.sealed.custodyManifest?.isEmpty == true)
        #expect(opened.sealed.shardOperations == nil || opened.sealed.shardOperations?.isEmpty == true)

        let reply = try pair.bob.run {
            try pair.bob.cm.encryptBundle(basket: CardPhone.basket("reply"), for: pair.bobSide, shardOperations: [], custodyManifest: [])
        }
        #expect(try pair.carol.receive(reply).text == "reply")
    }

    @Test("Shard content and a manifest in a bundle from a card contact are stripped on receive")
    func shardStrippedOnReceive() throws {
        let pair = try CardPhonePair()
        let (first, _) = try pair.redeem()
        try pair.bob.receive(first)

        // Carol is still imported: a second hand-built bootstrap bundle carrying shard content.
        let sealed = OccultaBundle.SealedPayload(
            message: try WireHandle.encode(basket: CardPhone.basket("with shards")),
            shardOperations: [.init(kind: .handback)], custodyManifest: [UUID(), UUID()], appVersion: Bundle.main.appVersion
        )
        var forgery = Forgery()
        forgery.sealed = sealed
        let bundle = try forgeBootstrap(from: pair.carol, to: pair.carolSide, forgery)

        let opened = try pair.bob.run { try pair.bob.cm.openGroup(bundle: try OccultaBundle.decoded(from: bundle)) }

        #expect(opened.sealed.shardOperations == nil || opened.sealed.shardOperations?.isEmpty == true)
        #expect(opened.sealed.custodyManifest == nil || opened.sealed.custodyManifest?.isEmpty == true)
        #expect(opened.recipientShardOperations == nil)
        #expect(opened.recipientCustodyManifest == nil)
        #expect(opened.ownerID == pair.bobSide)
    }

    @Test("An identity challenge from a card contact is rejected, and changes nothing")
    func challengeRejectedOnReceive() throws {
        let pair = try CardPhonePair()
        let (first, _) = try pair.redeem()
        try pair.bob.receive(first)
        let field = try pair.bob.rawField(pair.bobSide)
        let record = try pair.bob.record(pair.bobSide)

        var forgery = Forgery()
        forgery.sealed = .init(
            message: try WireHandle.encode(basket: CardPhone.basket("x")),
            identityChallenge: IdentityChallengeEnvelope(kind: .challenge, payload: Data(count: 72), contextNote: nil),
            appVersion: Bundle.main.appVersion
        )
        let bundle = try forgeBootstrap(from: pair.carol, to: pair.carolSide, forgery)

        #expect { try pair.bob.receive(bundle) } throws: { isUnrecognised($0) }
        #expect(try pair.bob.rawField(pair.bobSide) == field)
        #expect(try pair.bob.record(pair.bobSide) == record)
    }

    @Test("The ML-KEM vault eligibility filter and the group form's predicate exclude card contacts after a real conversation")
    func eligibilityAfterConversation() throws {
        let pair = try CardPhonePair()
        try pair.converse()
        try pair.bob.run {
            let contact = try pair.bob.contact(pair.bobSide)
            let key = try #require(try Manager.Ambient.keyManager.createHybridLocalEncryptionKey())
            #expect(contact.cardState(using: key).isCardContact)
        }
    }
}

// MARK: - 7: ordinary contacts beside card contacts

@MainActor
@Suite("Card conversation — ordinary contacts are unaffected", .serialized, .enabled(if: enclave))
struct CardNonCardRegressionTests {

    @Test("An ordinary pair converses unchanged beside a card conversation on the same device")
    func ordinaryBesideCard() throws {
        let pair = try CardPhonePair()
        let bob = pair.bob
        let eve = try CardPhone()
        try bob.addOrdinary(eve, as: "eve")
        try eve.addOrdinary(bob, as: "bob")

        // One round trip each way, interleaved with the card conversation.
        #expect(try bob.receive(try eve.send(to: "bob", "eve to bob")) == ("eve", "eve to bob"))
        let (first, _) = try pair.redeem()
        #expect(try eve.receive(try bob.send(to: "eve", "bob to eve")) == ("bob", "bob to eve"))
        try bob.receive(first)
        try pair.carol.receive(try bob.send(to: pair.bobSide, "reply"))
        #expect(try bob.receive(try eve.send(to: "bob", "again")).ownerID == "eve")
        #expect(try bob.receive(try pair.carol.send(to: pair.carolSide, "carol")).ownerID == pair.bobSide)

        // The ordinary contact has no card field state, and Eve's bundles never touch the card contact.
        #expect(try bob.state("eve") == .empty)
        guard case .conversation = try bob.state(pair.bobSide) else { Issue.record("should be a conversation"); return }
        #expect(try bob.run { try bob.cm.fetchAllContacts().count } == 2)
    }

    @Test("A bundle from an ordinary contact is not mistaken for a redemption, with an issued card out")
    func ordinaryWithIssuedCardOut() throws {
        let bob = try CardPhone(), eve = try CardPhone()
        try bob.addOrdinary(eve, as: "eve")
        try eve.addOrdinary(bob, as: "bob")
        let issuedSide = try bob.newContact("Issued")
        let card = try bob.run { try bob.cm.createCard(for: try bob.contact(issuedSide)) }

        #expect(try bob.receive(try eve.send(to: "bob", "hello")) == ("eve", "hello"))
        #expect(try bob.run { try bob.cm.ownIssuedAgreementKeys() } == [card.agreementKey], "the card is still out")
        guard case .issued = try bob.state(issuedSide) else { Issue.record("should still be issued"); return }
    }

    @Test("An ordinary contact's bundle to a device with no card contacts at all is unchanged")
    func noCardsAnywhere() throws {
        let alice = try CardPhone(), eve = try CardPhone()
        try alice.addOrdinary(eve, as: "eve")
        try eve.addOrdinary(alice, as: "alice")
        #expect(try alice.receive(try eve.send(to: "alice", "one")) == ("eve", "one"))
        #expect(try eve.receive(try alice.send(to: "eve", "two")) == ("alice", "two"))
    }
}

// MARK: - Helpers on ContactManager used above

private extension ContactManager {
    @MainActor
    func fetchAllContactsCount(in device: CardPhone) throws -> Int {
        try device.run { try self.fetchAllContacts().count }
    }
}

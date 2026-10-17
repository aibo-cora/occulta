//
//  ContactManager+Cards.swift
//  Occulta
//
//  The introduction card field (`Docs/Features/Introduction Cards/SPEC.md` §5): where a contact's `CardState`
//  is read from and sealed into `Contact.Profile.introductionCardEncrypted`. The format is `CardStateCodec`'s,
//  the rules `CardRules`'; this file loads, stores and derives the tier, and runs the procedures of SPEC §6.1 to
//  §6.4: create, cancel, share, import and the unlock sweep. The card's keys are `CardKeyProviding`'s and the
//  ML-KEM key's `PostQuantumProvider`'s, both injected into `ContactManager`.
//

import Foundation
import SwiftData
import CryptoKit
import OccultaCore
import OccultaFormats

extension Contact.Profile {

    /// The contact's card state, opened with the local DB key (`Manager.Crypto`, as every sealed field).
    /// A field that is nil, won't decrypt or won't decode reads as `.empty`, and never throws: the pass that
    /// fills the field retries at the next launch or unlock, and a contact the user can open must never fail to.
    var cardState: CardState {
        self.cardState(opening: { $0.decrypt() })
    }

    /// Same as `cardState`, under a local DB key the caller already derived, for passes over many contacts.
    func cardState(using key: SymmetricKey) -> CardState {
        self.cardState(opening: { $0.decrypt(using: key) })
    }

    private func cardState(opening open: (Data) -> Data?) -> CardState {
        guard
            let sealed = self.introductionCardEncrypted,
            let plaintext = open(sealed),
            let state = try? CardStateCodec().decode(plaintext)
        else { return .empty }
        return state
    }

    /// Whether the contact holds keys from an in-person exchange on this device: today's `.verified` test
    /// (`verificationStatus`), an unexpired key whose owner hash is ours.
    var hasInPersonKeys: Bool {
        guard let keys = self.contactPublicKeys, let latest = keys.last, latest.expiredOn == nil else { return false }

        let ownerHash = try? Manager.Crypto().decrypt(data: latest.owner)
        let ourHash   = (try? Manager.Ambient.keyManager.retrieveIdentity())?.sha256

        guard let ownerHash, let ourHash, !ownerHash.isEmpty else { return false }

        return ownerHash == ourHash
    }

    /// What the card says about the contact, computed from the field and the in-person keys and never stored.
    var cardTier: CardTier {
        CardRules.tier(self.cardState, hasInPersonKeys: self.hasInPersonKeys)
    }
}

extension ContactManager {

    /// Seals `state` into `contact`, at the fixed `CardStateCodec.capacity` whatever the state. Doesn't save;
    /// the caller does.
    func store(_ state: CardState, for contact: Contact.Profile) throws {
        guard let sealed = try CardStateCodec().encode(state).encrypt() else {
            throw CardStoreError.encryptionFailed
        }
        contact.introductionCardEncrypted = sealed
    }

    enum CardStoreError: Error {
        case encryptionFailed
    }

    enum CardError: Error, Equatable {
        /// Below iOS 26 (SPEC §1), where there is no ML-KEM key to put on a card.
        case unsupported
        /// A card needs a pending contact: not one holding `imported` or `conversation`, or in-person keys.
        case contactNotPending
        /// `cardShareFile`: the contact has no issued card.
        case noIssuedCard
        /// `discardCardConversation`: the contact's field isn't `conversation`.
        case noCardConversation
        /// Importing into a new contact needs a name.
        case newContactNameMissing
        /// A key, a signature or an encapsulation didn't come out. Nothing was stored.
        case keyGenerationFailed
        /// A card contact is refused shard content, an identity challenge and group traffic (SPEC §8).
        case hardBlocked
        /// `CardRules.canSend` says no: Carol's card has expired before she sent anything.
        case cannotSend
        /// The card field lacks what this send needs, or holds keys that won't parse. Nothing was sent.
        case keyMaterialMissing
    }

    // MARK: - Create and cancel (§6.1, §6.2)

    /// Bob: a card for `contact`, valid for 24 hours from `now`, whole seconds.
    ///
    /// Everything is generated before anything is stored, so a failure leaves the field as it was and no blob
    /// behind. An `issued` card already there is replaced, which cancels it: the field is the only copy of its keys.
    /// Throws `contactNotPending` for a field that is `imported` or `conversation`, or a contact with in-person keys.
    @discardableResult
    func createCard(for contact: Contact.Profile, now: Date = .now) throws -> IntroductionCard {
        guard let postQuantum = self.cardPostQuantum else { throw CardError.unsupported }
        switch contact.cardState {
        case .empty, .issued: break
        case .imported, .conversation: throw CardError.contactNotPending
        }
        guard !contact.hasInPersonKeys else { throw CardError.contactNotPending }

        let expiresAt = Date(timeIntervalSince1970: (now.timeIntervalSince1970 + Self.cardLifetime).rounded(.down))
        let agreement = try self.cardKeys.makeAgreementKey()
        let signing   = try self.cardKeys.makeSigningKey()
        guard let mlkem = postQuantum.generatePersistentKeyPair() else { throw CardError.keyGenerationFailed }

        let signature = try self.cardKeys.signRaw(
            IntroductionCard.signingPayload(
                agreementKey: agreement.publicKey, signingKey: signing.publicKey,
                expiresAt: expiresAt, mlkemEncapsulationKey: mlkem.publicKeyData
            ),
            signingBlob: signing.blob
        )
        let card = IntroductionCard(
            agreementKey: agreement.publicKey, signingKey: signing.publicKey, expiresAt: expiresAt,
            mlkemEncapsulationKey: mlkem.publicKeyData, signature: signature
        )
        // What we hand out must be what the other side recognises.
        guard IntroductionCard.recognize(card.encoded) == card else { throw CardError.keyGenerationFailed }

        let previous = contact.introductionCardEncrypted
        do {
            try self.store(
                .issued(card: card.encoded, agreementKey: agreement.blob, signingKey: signing.blob,
                        mlkemKey: mlkem.keyBlob, expiresAt: expiresAt),
                for: contact
            )
            try self.saveAndFlush()
        } catch {
            contact.introductionCardEncrypted = previous
            throw error
        }
        return card
    }

    /// Writes `.empty`. The blobs exist only in the field, so this deletes the keys; the checkpoint scrubs the
    /// write-ahead log's copy of them.
    func cancelCard(for contact: Contact.Profile) throws {
        try self.store(CardState.empty, for: contact)
        try self.saveAndFlush()
    }

    /// W-15 (SPEC §6.7): Bob discards a card conversation. The field is written `.empty`, which deletes the
    /// card keys, and the contact's record loses its inbound batches, own batches and accepted batch IDs, so
    /// the contact is Pending again. Only valid for `conversation`.
    func discardCardConversation(for contact: Contact.Profile) throws {
        guard case .conversation = contact.cardState else { throw CardError.noCardConversation }

        let previousField  = contact.introductionCardEncrypted
        let previousRecord = contact.prekeyRecordEncrypted
        do {
            try self.dropCardEraBatches(of: contact)
            try self.store(CardState.empty, for: contact)
            try self.saveAndFlush()
        } catch {
            contact.introductionCardEncrypted = previousField
            contact.prekeyRecordEncrypted = previousRecord
            throw error
        }
    }

    /// Drops the batches a card conversation made from `contact`'s record: inbound batches, own batches (and with
    /// them the Enclave keys they hold), accepted batch IDs. Doesn't save.
    private func dropCardEraBatches(of contact: Contact.Profile) throws {
        // An unreadable record is replaced by an empty one: everything in it is being dropped anyway.
        var record = (try? self.prekeyRecord(for: contact)) ?? .empty
        record.inboundBatches = []
        record.inboundLastResort = nil
        record.ownBatches = []
        record.acceptedBatchIDs = []
        record.latestInboundGeneratedAt = nil
        try self.store(record, for: contact)
    }

    // MARK: - Meeting check (§7)

    /// The meeting check's side of `contact`'s field, as values for `ExchangeManager.start(cardMeeting:)`. Signs
    /// whenever the field holds this side's card signing key (`issued`, `imported`, `conversation`); checks the
    /// peer's proof only where SPEC §7 shows a verdict: `imported` after a first send (against the signing key in
    /// `peerCard`) and `conversation` (against `peerSigningKey`).
    func cardMeetingContext(for contact: Contact.Profile) -> CardMeetingContext {
        let keys = self.cardKeys
        switch contact.cardState {
        case .empty:
            return .none
        case .issued(_, _, let signingKey, _, _):
            return CardMeetingContext(sign: { try keys.signRaw($0, signingBlob: signingKey) }, peerSigningKey: nil)
        case .imported(let peerCard, _, let signingKey, _, _, _, _, let sentFirstMessage):
            return CardMeetingContext(
                sign: { try keys.signRaw($0, signingBlob: signingKey) },
                peerSigningKey: sentFirstMessage ? IntroductionCard.recognize(peerCard)?.signingKey : nil
            )
        case .conversation(_, let signingKey, _, let peerSigningKey, _, _, _, _):
            return CardMeetingContext(sign: { try keys.signRaw($0, signingBlob: signingKey) }, peerSigningKey: peerSigningKey)
        }
    }

    /// The exchange's save (`update(key:for:)`) calls this for the contact it stores keys for: the card field is
    /// written `.empty`, which deletes every card key, and any card state's batches go from the record. A field that
    /// was already `.empty` leaves the record alone (an ordinary re-exchange keeps its prekeys). Doesn't save.
    /// Nothing about the verdict is stored.
    ///
    /// - Returns: whether a card key could have existed, so the caller checkpoints after its save.
    @discardableResult
    func clearCard(afterMeetingOf contact: Contact.Profile) throws -> Bool {
        let hadCard = contact.cardState != .empty
        if hadCard { try self.dropCardEraBatches(of: contact) }
        try self.store(CardState.empty, for: contact)
        return hadCard
    }

    // MARK: - Share (§2)

    /// The issued card's bytes in a temporary file for the share sheet: a random 12-hex-character name, no
    /// extension, protected and out of backups. The caller deletes it after sharing; the app's launch and
    /// background clean-up of the temporary directory catches one it doesn't.
    func cardShareFile(for contact: Contact.Profile) throws -> URL {
        guard case .issued(let card, _, _, _, _) = contact.cardState else { throw CardError.noIssuedCard }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(Data.randomBytes(6).hexEncodedString())
        try card.writeProtected(to: url)
        return url
    }

    // MARK: - Import (§6.3)

    /// The agreement public key of every card we have issued, on every contact at every depth: what makes a card
    /// one of our own (`CardRules.importDecision`).
    func ownIssuedAgreementKeys() throws -> Set<Data> {
        var keys = Set<Data>()
        for contact in try self.fetchAllContacts() {
            if case .issued(let card, _, _, _, _) = contact.cardState, let own = IntroductionCard.recognize(card) {
                keys.insert(own.agreementKey)
            }
        }
        return keys
    }

    /// Carol: imports `data` into `contact`, or into a new contact named `newContactName` at the current depth.
    ///
    /// Not a card gives `.notACard`; below iOS 26, `.unsupported`. Otherwise `CardRules.importDecision` decides.
    /// Her keys, her ML-KEM key and her pending prekey batch are generated, and the one encapsulation to Bob's
    /// ML-KEM key made, before anything is stored. Replacing or cancelling overwrites the old state, which
    /// deletes its keys, and drops the pending batch the old import made. Throws `contactNotPending` for a contact
    /// with in-person keys.
    @discardableResult
    func importCard(_ data: Data, into contact: Contact.Profile?, newContactName: String?, now: Date = .now) throws -> CardImportOutcome {
        guard let card = IntroductionCard.recognize(data) else { return .notACard }
        guard let postQuantum = self.cardPostQuantum else { return .unsupported }

        switch CardRules.importDecision(
            current: contact?.cardState ?? .empty, incoming: card, now: now,
            ownIssuedAgreementKeys: try self.ownIssuedAgreementKeys()
        ) {
        case .refuse(let refusal): return .refused(refusal)
        case .importNew, .replace, .cancelOwnAndImport: break
        }
        if let contact, contact.hasInPersonKeys { throw CardError.contactNotPending }

        let name = (newContactName ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        if contact == nil, name.isEmpty { throw CardError.newContactNameMissing }

        let agreement = try self.cardKeys.makeAgreementKey()
        let signing   = try self.cardKeys.makeSigningKey()
        guard
            let mlkem = postQuantum.generatePersistentKeyPair(),
            let encapsulation = postQuantum.encapsulate(peerPublicKeyData: card.mlkemEncapsulationKey)
        else { throw CardError.keyGenerationFailed }

        let target = try contact ?? self.createPendingContact(named: name)

        let previousField  = target.introductionCardEncrypted
        let previousRecord = target.prekeyRecordEncrypted
        do {
            // A pending batch is the old import's: nothing has been delivered from it, so nothing is lost.
            var record = try self.prekeyRecord(for: target)
            record.ownBatches.removeAll(where: \.isPending)
            try self.installFreshBatch(into: &record)
            try self.store(record, for: target)
            try self.store(
                .imported(
                    peerCard: card.encoded, agreementKey: agreement.blob, signingKey: signing.blob, mlkemKey: mlkem.keyBlob,
                    ss1: encapsulation.sharedSecret, ct1: encapsulation.ciphertext, expiresAt: card.expiresAt,
                    sentFirstMessage: false
                ),
                for: target
            )
            try self.saveAndFlush()
        } catch {
            target.introductionCardEncrypted = previousField
            target.prekeyRecordEncrypted = previousRecord
            throw error
        }
        return .imported(contactIdentifier: target.identifier)
    }

    /// A new contact at the current depth, found again by comparing the identifiers before and after, since the
    /// stored identifier is sealed.
    private func createPendingContact(named name: String) throws -> Contact.Profile {
        let before = Set(try self.fetchAllContacts().map(\.identifier))
        try self.save(contact: Contact.Draft(identifier: UUID().uuidString, givenName: name), currentDepth: self.security.currentDepth)
        guard let created = try self.fetchAllContacts().first(where: { !before.contains($0.identifier) }) else {
            throw ContactManager.Errors.contactNotFound
        }
        return created
    }

    // MARK: - Expiry (§6.4)

    /// The unlock sweep: `CardRules.sweep` over every contact at every depth. A cleared card is written `.empty`
    /// at the same size; Carol's also drops the pending prekey batch she made at import, which was never delivered
    /// (she hasn't sent, so nothing has used it). Saves once. A contact that fails doesn't stop the others; the
    /// first error is thrown at the end.
    func sweepCards(now: Date = .now) throws {
        var changed = false
        var firstError: Error?

        for contact in try self.fetchAllContacts() {
            let state = contact.cardState
            guard CardRules.sweep(state, now: now) == .clear else { continue }
            do {
                if case .imported = state, var record = try? self.prekeyRecord(for: contact) {
                    record.ownBatches.removeAll(where: \.isPending)
                    try self.store(record, for: contact)
                }
                try self.store(CardState.empty, for: contact)
                changed = true
            } catch {
                firstError = firstError ?? error
            }
        }

        if changed { try self.saveAndFlush() }
        if let firstError { throw firstError }
    }

    private static let cardLifetime: TimeInterval = 24 * 60 * 60

    // MARK: - For compose

    /// Whether the compose indicator says Standard Encryption: Carol's slots, sealed to Bob's card key while she
    /// holds none of his prekeys (SPEC §4.3). True while the field is `imported`.
    func cardSecrecyIsStandard(for contact: Contact.Profile) -> Bool {
        if case .imported = contact.cardState { return true }
        return false
    }

    /// `CardRules.canSend` for the contact's field.
    func canSendToCardContact(_ contact: Contact.Profile) -> Bool {
        CardRules.canSend(contact.cardState, now: .now)
    }

    // MARK: - Send (§6.5)

    /// A bundle for a contact whose field is `imported` or `conversation`: the group format with one slot, sent
    /// under the card keys (SPEC §3).
    ///
    /// | State | Slot |
    /// |---|---|
    /// | Carol `imported` | bootstrap with `ct1` and her introduction, to Bob's card agreement key |
    /// | Bob `conversation`, `bootstrapOpen` | bootstrap with `ct2`, to Carol's batch or long-term |
    /// | `conversation` otherwise | ordinary hybrid slot with the stored material |
    ///
    /// Everything that can fail runs before anything is stored, and any failure throws: a card contact never gets
    /// a classical-only or identity-key bundle in its place. Carol's first send sets `sentFirstMessage` and saves
    /// it before the bundle is returned. Only a basket is accepted: shard content and identity challenges are
    /// refused (SPEC §8).
    func encryptCardBundle(
        basket: Basket?,
        for contact: Contact.Profile,
        shardOperations: [OccultaBundle.ShardOperation]? = nil,
        custodyManifest: [UUID]? = nil,
        identityChallenge: IdentityChallengeEnvelope? = nil
    ) throws -> Data {
        guard let basket, shardOperations == nil, custodyManifest == nil, identityChallenge == nil else {
            throw CardError.hardBlocked
        }
        let state = contact.cardState
        guard CardRules.canSend(state, now: .now) else { throw CardError.cannotSend }

        let cryptoOps = Manager.Crypto()
        var record = try self.prekeyRecord(for: contact)
        var prekey: Prekey?
        var prekeyIsLastResort = false
        var quantum: QuantumKeyMaterial?
        let peerAgreementKey: Data
        let slot: CardSlot
        var advancedState: CardState?

        switch state {
        case .imported(let peerCard, let agreementKey, let signingKey, let mlkemKey, let ss1, let ct1, let expiresAt, let sentFirstMessage):
            guard let peer = IntroductionCard.recognize(peerCard), let postQuantum = self.cardPostQuantum else {
                throw CardError.keyMaterialMissing
            }
            let ownAgreementKey = try self.cardKeys.agreementPublicKey(blob: agreementKey)
            let introduction = try self.makeIntroduction(
                answering: peer, agreementKey: ownAgreementKey, signingBlob: signingKey, mlkemBlob: mlkemKey, postQuantum: postQuantum
            )
            slot = CardSlot(
                keys: self.cardKeys, agreementBlob: agreementKey, signingBlob: signingKey, ownAgreementKey: ownAgreementKey,
                bootstrap: .carol(ss1: ss1, ct1: ct1, introduction: introduction)
            )
            peerAgreementKey = peer.agreementKey
            if !sentFirstMessage {
                advancedState = .imported(
                    peerCard: peerCard, agreementKey: agreementKey, signingKey: signingKey, mlkemKey: mlkemKey,
                    ss1: ss1, ct1: ct1, expiresAt: expiresAt, sentFirstMessage: true
                )
            }

        case .conversation(let agreementKey, let signingKey, let peerKey, _, _, let held, let bootstrapOpen, _):
            guard let held else { throw CardError.keyMaterialMissing }
            quantum = held
            slot = CardSlot(
                keys: self.cardKeys, agreementBlob: agreementKey, signingBlob: signingKey,
                ownAgreementKey: try self.cardKeys.agreementPublicKey(blob: agreementKey),
                bootstrap: bootstrapOpen ? .bob(ct2: held.ourCiphertext) : nil
            )
            peerAgreementKey = peerKey
            // Carol's pending batch rides this message; Bob's one-time key is taken off the record in memory, and
            // stored only once the bundle has been built.
            prekey = PrekeyBookkeeper().takeInboundPrekey(from: &record, contactID: contact.identifier)
            if prekey == nil {
                prekey = PrekeyBookkeeper().lastResortPrekey(in: record, contactID: contact.identifier)
                prekeyIsLastResort = prekey != nil
            }

        case .empty, .issued:
            throw CardError.hardBlocked
        }

        let bundle = try cryptoOps.seal(
            sealedPayload: OccultaBundle.SealedPayload(
                message: try WireHandle.encode(basket: basket), appVersion: Bundle.main.appVersion
            ),
            groupID: UUID(),
            recipients: [GroupRecipient(
                publicKey: peerAgreementKey,
                quantumMaterial: quantum,
                contactPrekey: prekey,
                contactPrekeyIsLastResort: prekeyIsLastResort,
                pendingBatch: self.pendingBatchForWire(in: record),
                prefixesEphemeralSignature: true,
                card: slot
            )],
            senderIdentity: slot.ownAgreementKey
        )
        let encoded = try bundle.encoded(version: .v4)

        // Now that the bundle exists: the used key, and Carol's first send, saved before it is handed off.
        let previousField  = contact.introductionCardEncrypted
        let previousRecord = contact.prekeyRecordEncrypted
        do {
            if prekey != nil, !prekeyIsLastResort { try self.store(record, for: contact) }
            if let advancedState { try self.store(advancedState, for: contact) }
            if advancedState != nil || (prekey != nil && !prekeyIsLastResort) { try self.saveAndFlush() }
        } catch {
            contact.introductionCardEncrypted = previousField
            contact.prekeyRecordEncrypted = previousRecord
            throw error
        }
        return encoded
    }

    /// Carol's introduction (SPEC §4.4): her card keys, signed by her card signing key over Bob's card digest.
    /// Signed afresh for each message, so the signature bytes differ; the keys are the same.
    private func makeIntroduction(
        answering card: IntroductionCard,
        agreementKey: Data,
        signingBlob: Data,
        mlkemBlob: Data,
        postQuantum: any PostQuantumProvider
    ) throws -> CardIntroduction {
        guard let mlkemKey = postQuantum.publicKey(forKeyBlob: mlkemBlob) else { throw CardError.keyMaterialMissing }
        let signingKey = try self.cardKeys.signingPublicKey(blob: signingBlob)
        let signature = try self.cardKeys.signDER(
            CardIntroduction.signingPayload(
                cardDigest: card.digest, agreementKey: agreementKey, signingKey: signingKey, mlkemEncapsulationKey: mlkemKey
            ),
            signingBlob: signingBlob
        )
        return CardIntroduction(agreementKey: agreementKey, signingKey: signingKey, mlkemEncapsulationKey: mlkemKey, signature: signature)
    }

    // MARK: - Receive (§6.6)

    /// What this contact's field lets us open with, or nil when it holds no card conversation.
    func cardReceiveContext(for contact: Contact.Profile) throws -> CardReceiveContext? {
        switch contact.cardState {
        case .imported(let peerCard, let agreementKey, _, let mlkemKey, let ss1, let ct1, _, _):
            guard let peer = IntroductionCard.recognize(peerCard), let postQuantum = self.cardPostQuantum else {
                throw CardError.keyMaterialMissing
            }
            return CardReceiveContext(
                role: .carol, keys: self.cardKeys, agreementBlob: agreementKey,
                ownAgreementKey: try self.cardKeys.agreementPublicKey(blob: agreementKey),
                peerAgreementKey: peer.agreementKey, peerSigningKey: peer.signingKey, quantum: nil,
                pending: .init(ss1: ss1, ct1: ct1, mlkemBlob: mlkemKey, postQuantum: postQuantum)
            )
        case .conversation(let agreementKey, _, let peerAgreementKey, let peerSigningKey, _, let quantum, _, let peerIntroduction):
            // Carol until she holds `ss2` is `imported`; a `conversation` always has the material.
            return CardReceiveContext(
                role: peerIntroduction != nil ? .bob : .carol, keys: self.cardKeys, agreementBlob: agreementKey,
                ownAgreementKey: try self.cardKeys.agreementPublicKey(blob: agreementKey),
                peerAgreementKey: peerAgreementKey, peerSigningKey: peerSigningKey, quantum: quantum, pending: nil
            )
        case .empty, .issued:
            return nil
        }
    }

    /// The key a bundle from this contact's card conversation is identified by: the peer's card agreement key.
    /// Bob's, read from `peerCard`, for `imported`; the stored one for `conversation`.
    func cardPeerAgreementKey(of contact: Contact.Profile, using key: SymmetricKey) -> Data? {
        switch contact.cardState(using: key) {
        case .imported(let peerCard, _, _, _, _, _, _, _): return IntroductionCard.recognize(peerCard)?.agreementKey
        case .conversation(_, _, let peerAgreementKey, _, _, _, _, _): return peerAgreementKey
        case .empty, .issued: return nil
        }
    }

    /// After a card slot opened and every check passed (SPEC §6.6 step 3). Doesn't save; `save(_:for:)` does.
    ///
    /// - Bob rejects an introduction other than the one he redeemed, compared by its keys (see
    ///   `sameIntroduction`), and a bootstrap slot without one.
    /// - Carol's first message from Bob gives her `ss2`: the field becomes `conversation` with full material,
    ///   and her ML-KEM key goes with the old state.
    /// - Bob's first non-bootstrap slot from Carol closes his bootstrap.
    func applyCardOpening(_ opening: CardSlotOpening, to contact: Contact.Profile) throws {
        switch contact.cardState {
        case .imported(let peerCard, let agreementKey, let signingKey, _, _, _, _, _):
            guard let quantum = opening.derivedQuantum, let peer = IntroductionCard.recognize(peerCard) else { return }
            try self.store(
                .conversation(
                    agreementKey: agreementKey, signingKey: signingKey,
                    peerAgreementKey: peer.agreementKey, peerSigningKey: peer.signingKey,
                    mlkemKey: nil, quantum: quantum, bootstrapOpen: false, peerIntroduction: nil
                ),
                for: contact
            )

        case .conversation(let agreementKey, let signingKey, let peerAgreementKey, let peerSigningKey, let mlkemKey, let quantum, let bootstrapOpen, let peerIntroduction)
            where peerIntroduction != nil && bootstrapOpen && !opening.wasBootstrap:
            try self.store(
                .conversation(
                    agreementKey: agreementKey, signingKey: signingKey, peerAgreementKey: peerAgreementKey,
                    peerSigningKey: peerSigningKey, mlkemKey: mlkemKey, quantum: quantum,
                    bootstrapOpen: false, peerIntroduction: peerIntroduction
                ),
                for: contact
            )

        case .empty, .issued, .imported, .conversation:
            return
        }
    }

    /// Bob's check on an opened slot: a bootstrap slot from Carol carries her introduction, and any introduction
    /// is the one he redeemed. Throws `GroupDecryptError.cardIntroductionMismatch`.
    func checkCardIntroduction(_ opening: CardSlotOpening, for contact: Contact.Profile) throws {
        guard case .conversation(_, _, _, _, _, _, _, let stored?) = contact.cardState else { return }
        guard let introduction = opening.payload.introduction else {
            if opening.wasBootstrap { throw GroupDecryptError.cardIntroductionMismatch }
            return
        }
        guard let known = try? JSONDecoder().decode(CardIntroduction.self, from: stored),
              Self.sameIntroduction(known, introduction)
        else { throw GroupDecryptError.cardIntroductionMismatch }
    }

    /// Whether two introductions name the same keys. Compared by keys, not bytes: Carol signs afresh for each
    /// message and an ECDSA signature differs every time, so the signature can't be part of the comparison. Bob
    /// checked it against the card once, at redemption; afterwards the slot's own signature authenticates her.
    static func sameIntroduction(_ a: CardIntroduction, _ b: CardIntroduction) -> Bool {
        a.agreementKey == b.agreementKey && a.signingKey == b.signingKey && a.mlkemEncapsulationKey == b.mlkemEncapsulationKey
    }

    // MARK: - Redemption (§6.6 step 4)

    /// The contact whose `issued` card this bundle redeems, or nil. Runs when no contact matches the bundle's
    /// sender fingerprint, at every depth.
    ///
    /// For each `issued` contact and each forward-secret slot: ECDH of the card agreement key with the slot's
    /// ephemeral key, the bootstrap layer, `ct1` decapsulated with the card's ML-KEM key, then the checks in
    /// order: the introduction's signature against this card's digest; `senderEphemeralSignature` under its
    /// signing key; `senderFingerprint` against its agreement key; `bodyDigest`, the body and `senderProof`.
    /// A card that fails any check stays `issued` and nothing is generated or consumed. When all pass: encapsulate
    /// to Carol's ML-KEM key (`ss2`, `ct2`), store `conversation` (`bootstrapOpen`, full material, no ML-KEM
    /// key), save with a checkpoint. Carol's batch and Bob's first batch are the ordinary receive path's, which
    /// opens this bundle next (`openGroup`) and generates after its own checks (Bug 159). An expired card is
    /// cancelled and skipped.
    func redeemCard(for bundle: OccultaBundle, now: Date = .now) throws -> Contact.Profile? {
        guard let postQuantum = self.cardPostQuantum, let envelope = bundle.group,
              envelope.recipients.count <= Group.slotCount else { return nil }

        let cryptoOps = Manager.Crypto()
        for contact in try self.fetchAllContacts() {
            guard case .issued(let cardBytes, let agreementBlob, let signingBlob, let mlkemBlob, let expiresAt) = contact.cardState else { continue }

            guard expiresAt > now else {
                try self.cancelCard(for: contact)
                continue
            }
            guard let card = IntroductionCard.recognize(cardBytes) else { continue }

            for entry in envelope.recipients where entry.secrecyContext.mode == .forwardSecret && entry.secrecyContext.ephemeralPublicKey.count == 65 {
                let ephemeral = entry.secrecyContext.ephemeralPublicKey
                guard
                    let raw = try? self.cardKeys.sharedSecret(agreementBlob: agreementBlob, peerPublicKey: ephemeral),
                    let outcome = Self.redeemSlot(
                        entry, bundle: bundle, blind: envelope.blind, card: card, mlkemBlob: mlkemBlob,
                        ecdhOutput: Manager.Crypto.cardECDHOutput(raw), postQuantum: postQuantum, cryptoOps: cryptoOps
                    ),
                    let encapsulation = postQuantum.encapsulate(peerPublicKeyData: outcome.introduction.mlkemEncapsulationKey),
                    let storedIntroduction = try? JSONEncoder().encode(outcome.introduction)
                else { continue }

                // `ss1` is what Bob decapsulated, `ss2` what he just encapsulated: Carol holds them the other way
                // round, and the key derivation sorts them.
                let quantum = QuantumKeyMaterial(
                    encapsulatedSecret: encapsulation.sharedSecret, decapsulatedSecret: outcome.ss1,
                    ourCiphertext: encapsulation.ciphertext, peerCiphertext: outcome.ct1
                )
                let previous = contact.introductionCardEncrypted
                do {
                    try self.store(
                        .conversation(
                            agreementKey: agreementBlob, signingKey: signingBlob,
                            peerAgreementKey: outcome.introduction.agreementKey, peerSigningKey: outcome.introduction.signingKey,
                            mlkemKey: nil, quantum: quantum, bootstrapOpen: true, peerIntroduction: storedIntroduction
                        ),
                        for: contact
                    )
                    try self.saveAndFlush()
                } catch {
                    contact.introductionCardEncrypted = previous
                    throw error
                }
                return contact
            }
        }
        return nil
    }

    /// One slot against one card; nil unless it opens and every check passes.
    private static func redeemSlot(
        _ entry: OccultaBundle.Recipient,
        bundle: OccultaBundle,
        blind: Data,
        card: IntroductionCard,
        mlkemBlob: Data,
        ecdhOutput: Data,
        postQuantum: any PostQuantumProvider,
        cryptoOps: Manager.Crypto
    ) -> (introduction: CardIntroduction, ss1: Data, ct1: Data)? {
        let ephemeral = entry.secrecyContext.ephemeralPublicKey
        guard
            let outerKey = Manager.Key.forwardSecretSessionKey(
                ecdhOutput: ecdhOutput, ownPublicKey: card.agreementKey, peerMaterial: ephemeral, quantumMaterial: nil
            ),
            let layer = try? CardBootstrap.openOuter(entry.wrappedPayload, outerKey: outerKey, blind: blind),
            let ss1 = postQuantum.decapsulate(ciphertext: layer.mlkemCiphertext, keyBlob: mlkemBlob),
            let innerKey = CardBootstrap.carolInnerKey(ecdhOutput: ecdhOutput, ownPublicKey: card.agreementKey, peerPublicKey: ephemeral, ss1: ss1),
            let plain = try? CardBootstrap.openInner(layer.inner, mlkemCiphertext: layer.mlkemCiphertext, innerKey: innerKey, blind: blind),
            let payload = try? JSONDecoder().decode(OccultaBundle.RecipientPayload.self, from: plain)
        else { return nil }

        // 1. The introduction's signature, against this card's digest.
        guard let introduction = payload.introduction, introduction.verify(cardDigest: card.digest) else { return nil }
        // 2. The slot's signature, under the introduction's signing key.
        guard let signature = payload.senderEphemeralSignature,
              cryptoOps.verifySenderEphemeralSignature(
                  signature, ephemeralPublicKey: ephemeral, senderPublicKey: introduction.signingKey, acceptsBareForm: false
              )
        else { return nil }
        // 3. The routing fingerprint, against the introduction's agreement key.
        guard OccultaBundle.SecrecyContext.fingerprint(for: introduction.agreementKey, nonce: bundle.fingerprintNonce) == bundle.senderFingerprint else {
            return nil
        }
        // 4. The body: its digest, then the body itself and its proof, as the ordinary receive path will check them.
        guard
            payload.bodyDigest == Data(SHA256.hash(data: bundle.ciphertext)),
            let body = try? cryptoOps.openGroupCiphertext(bundle, using: SymmetricKey(data: payload.sessionKey)),
            let decoded = try? WireHandle.decode(payload: body),
            decoded.identityChallenge == nil,
            decoded.groupID != nil,
            let proof = decoded.senderProof,
            HMAC<SHA256>.isValidAuthenticationCode(proof, authenticating: introduction.agreementKey, using: SymmetricKey(data: payload.sessionKey))
        else { return nil }

        return (introduction, ss1, layer.mlkemCiphertext)
    }
}

/// What importing a card did (`ContactManager.importCard`).
enum CardImportOutcome: Equatable {
    case imported(contactIdentifier: String)
    case refused(CardImportDecision.Refusal)
    case notACard
    case unsupported
}

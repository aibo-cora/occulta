//
//  Crypto+Manager+Cards.swift
//  Occulta
//
//  The crypto of a card conversation's slots (`Docs/Features/Introduction Cards/SPEC.md` §3, §4.3, §6.5): sealing
//  one (`wrapCardRecipient`) and opening one (`openCardSlot`). The group bundle around the slot is the existing
//  one; what differs is whose keys stand in for the identity key, and the bootstrap layer.
//
//  Nothing here reads a contact or writes a record. `ContactManager+Cards.swift` builds the contexts and applies
//  the outcomes.
//

import Foundation
import CryptoKit
import OccultaCore
import OccultaFormats

// MARK: - Sending

/// What `wrapCardRecipient` needs to build one card-conversation slot, beside `GroupRecipient`'s own fields
/// (`publicKey` is the peer's card agreement key; `quantumMaterial` is the conversation's material, nil for
/// Carol's slots, which carry `ss1` instead).
struct CardSlot {

    enum Bootstrap {
        /// Carol, until she opens a message from Bob: sealed ephemeral to static to Bob's card agreement key,
        /// under a random `prekeyID`, with her introduction.
        case carol(ss1: Data, ct1: Data, introduction: CardIntroduction)
        /// Bob, until he opens a non-bootstrap message from Carol: to her batch or the card keys, with `ct2`.
        case bob(ct2: Data)
    }

    let keys: any CardKeyProviding
    let agreementBlob: Data
    let signingBlob: Data
    /// This side's card agreement public key, the identity it sends under.
    let ownAgreementKey: Data
    /// Nil for an ordinary hybrid slot with the stored material.
    let bootstrap: Bootstrap?
}

extension Manager.Crypto {

    enum CardCryptoError: Error {
        /// A slot that needs the conversation's material and has none. Never answered with a classical slot.
        case quantumMaterialMissing
    }

    /// One slot of a card conversation (SPEC §3, §6.5).
    ///
    /// - Carol's bootstrap: ECDH(fresh ephemeral, Bob's card agreement key), `prekeyID` a random UUID.
    /// - Otherwise, to the peer's prekey if one was taken, else long-term between the two card agreement keys.
    /// - In every case `K_outer` is classical and `K_inner` carries an ML-KEM secret; an ordinary slot has
    ///   neither layer, only the hybrid key.
    func wrapCardRecipient(
        _ r: GroupRecipient,
        card: CardSlot,
        sessionKeyData: Data,
        blind: Data,
        bodyDigest: Data
    ) throws -> OccultaBundle.Recipient {
        let ecdhOutput: Data
        let own: Data
        let peer: Data
        let context: OccultaBundle.SecrecyContext
        let usesEphemeral: Bool

        if case .carol = card.bootstrap {
            let ephemeral = try self.freshEphemeralKey()
            ecdhOutput = try Self.ephemeralECDHOutput(ephemeral.privateKey, peerPublicKey: r.publicKey)
            (own, peer, usesEphemeral) = (ephemeral.publicKeyData, r.publicKey, true)
            context = OccultaBundle.SecrecyContext(mode: .forwardSecret, ephemeralPublicKey: ephemeral.publicKeyData, prekeyID: UUID().uuidString)
        } else if let prekey = r.contactPrekey {
            guard prekey.publicKey.count == 65 else { throw EncryptionError.invalidPrekeyMaterial }
            let ephemeral = try self.freshEphemeralKey()
            ecdhOutput = try Self.ephemeralECDHOutput(ephemeral.privateKey, peerPublicKey: prekey.publicKey)
            (own, peer, usesEphemeral) = (ephemeral.publicKeyData, prekey.publicKey, true)

            let prekeyID: String
            if r.contactPrekeyIsLastResort {
                guard let derived = OccultaBundle.SecrecyContext.lastResortPrekeyID(
                    keyID: prekey.id, ephemeralPublicKey: ephemeral.publicKeyData
                ) else { throw EncryptionError.invalidPrekeyMaterial }
                prekeyID = derived
            } else {
                prekeyID = prekey.id
            }
            context = OccultaBundle.SecrecyContext(mode: .forwardSecret, ephemeralPublicKey: ephemeral.publicKeyData, prekeyID: prekeyID)
        } else {
            ecdhOutput = Self.cardECDHOutput(try card.keys.sharedSecret(agreementBlob: card.agreementBlob, peerPublicKey: r.publicKey))
            (own, peer, usesEphemeral) = (card.ownAgreementKey, r.publicKey, false)
            context = OccultaBundle.SecrecyContext(mode: .longTermFallback, ephemeralPublicKey: Data(), prekeyID: nil)
        }

        let senderEphemeralSignature = usesEphemeral
            ? try card.keys.signDER(Self.ephemeralSignaturePayload(context.ephemeralPublicKey), signingBlob: card.signingBlob)
            : Self.randomEphemeralSignatureFiller()

        var introduction: CardIntroduction?
        if case .carol(_, _, let carolIntroduction) = card.bootstrap { introduction = carolIntroduction }

        let payload = OccultaBundle.RecipientPayload(
            sessionKey:               sessionKeyData,
            prekeyBatch:              r.pendingBatch,
            shardMetadataAttempted:   false,
            senderEphemeralSignature: senderEphemeralSignature,
            bodyDigest:               bodyDigest,
            introduction:             introduction
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let encodedPayload = try encoder.encode(payload)

        let wrapped: Data
        switch card.bootstrap {
        case .carol(let ss1, let ct1, _):
            guard
                let outerKey = Manager.Key.forwardSecretSessionKey(ecdhOutput: ecdhOutput, ownPublicKey: own, peerMaterial: peer, quantumMaterial: nil),
                let innerKey = CardBootstrap.carolInnerKey(ecdhOutput: ecdhOutput, ownPublicKey: own, peerPublicKey: peer, ss1: ss1)
            else { throw EncryptionError.keyDerivationFailed }
            wrapped = try CardBootstrap.seal(payload: encodedPayload, mlkemCiphertext: ct1, outerKey: outerKey, innerKey: innerKey, blind: blind)

        case .bob(let ct2):
            guard let quantum = r.quantumMaterial else { throw CardCryptoError.quantumMaterialMissing }
            guard
                let outerKey = Manager.Key.forwardSecretSessionKey(ecdhOutput: ecdhOutput, ownPublicKey: own, peerMaterial: peer, quantumMaterial: nil),
                let innerKey = Manager.Key.forwardSecretSessionKey(ecdhOutput: ecdhOutput, ownPublicKey: own, peerMaterial: peer, quantumMaterial: quantum)
            else { throw EncryptionError.keyDerivationFailed }
            wrapped = try CardBootstrap.seal(payload: encodedPayload, mlkemCiphertext: ct2, outerKey: outerKey, innerKey: innerKey, blind: blind)

        case nil:
            guard let quantum = r.quantumMaterial else { throw CardCryptoError.quantumMaterialMissing }
            guard let key = usesEphemeral
                ? Manager.Key.forwardSecretSessionKey(ecdhOutput: ecdhOutput, ownPublicKey: own, peerMaterial: peer, quantumMaterial: quantum)
                : Self.cardLongTermKey(ecdhOutput: ecdhOutput, ownPublicKey: own, peerPublicKey: peer, quantumMaterial: quantum)
            else { throw EncryptionError.keyDerivationFailed }
            guard let sealed = try AES.GCM.seal(encodedPayload, using: key, nonce: AES.GCM.Nonce(), authenticating: blind).combined else {
                throw EncryptionError.sealFailed
            }
            wrapped = sealed
        }

        return OccultaBundle.Recipient(secrecyContext: context, wrappedPayload: wrapped)
    }

    private func freshEphemeralKey() throws -> (privateKey: SecKey, publicKeyData: Data) {
        guard let pair = self.keyManager.generateEphemeralKeyPair() else { throw EncryptionError.ephemeralKeyGenerationFailed }
        return (pair.privateKey, pair.publicKeyData)
    }

    // MARK: - ECDH and the long-term key

    /// CryptoKit's raw shared secret through the X9.63 KDF (SHA-256, no shared info, 32 bytes): the "ECDH output"
    /// every derivation in the app starts from, as `.ecdhKeyExchangeCofactorX963SHA256` gives it. For a single
    /// 32-byte block this is `SHA-256(secret ‖ 00000001)`.
    static func cardECDHOutput(_ rawSharedSecret: Data) -> Data {
        var input = rawSharedSecret
        input.append(contentsOf: [0, 0, 0, 1])
        return Data(SHA256.hash(data: input))
    }

    /// The ECDH output of a throwaway software key against an X9.63 public key.
    static func ephemeralECDHOutput(_ privateKey: SecKey, peerPublicKey: Data) throws -> Data {
        guard peerPublicKey.count == 65 else { throw EncryptionError.invalidRecipientMaterial }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String:      kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        guard
            let peerKey = SecKeyCreateWithData(peerPublicKey as CFData, attributes as CFDictionary, &error),
            let output = SecKeyCopyKeyExchangeResult(
                privateKey, .ecdhKeyExchangeCofactorX963SHA256, peerKey,
                [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32] as CFDictionary, &error
            ) as? Data
        else { throw EncryptionError.keyDerivationFailed }
        return output
    }

    /// The long-term slot key between the two card agreement keys: the derivation of `createHybridSharedSecret`
    /// (SPEC §3), with the card keys in place of the identity keys.
    static func cardLongTermKey(ecdhOutput: Data, ownPublicKey: Data, peerPublicKey: Data, quantumMaterial: QuantumKeyMaterial) -> SymmetricKey? {
        guard ownPublicKey.count == 65, peerPublicKey.count == 65, quantumMaterial.isValid else { return nil }
        let sorted = [quantumMaterial.encapsulatedSecret, quantumMaterial.decapsulatedSecret]
            .sorted { $0.lexicographicallyPrecedes($1) }
        var ikm = ecdhOutput
        ikm.append(contentsOf: sorted[0])
        ikm.append(contentsOf: sorted[1])
        let salt = Data(zip(peerPublicKey, ownPublicKey).map { $0 ^ $1 })
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm), salt: salt, info: SaltInfo.kHybridTransportKeyInfo, outputByteCount: 32
        )
    }
}

// MARK: - Receiving

/// What a side holds to open a card conversation's slots, built by `ContactManager.cardReceiveContext(for:)`
/// from the contact's card field.
struct CardReceiveContext {

    enum Role {
        /// The card's recipient: opens Bob's bootstrap slots (`K_inner` from `ss1` and `ss2`).
        case carol
        /// The card's issuer: opens Carol's bootstrap slots, sealed to his card agreement key (`K_inner` from `ss1`).
        case bob
    }

    /// Carol's material until Bob's first message gives her `ss2`.
    struct Pending {
        let ss1: Data
        let ct1: Data
        let mlkemBlob: Data
        let postQuantum: any PostQuantumProvider
    }

    let role: Role
    let keys: any CardKeyProviding
    let agreementBlob: Data
    let ownAgreementKey: Data
    let peerAgreementKey: Data
    let peerSigningKey: Data
    /// Full material, once held.
    let quantum: QuantumKeyMaterial?
    let pending: Pending?
}

/// A card slot that opened.
struct CardSlotOpening {
    let payload: OccultaBundle.RecipientPayload
    let used: InboundPrekeyUse
    let mode: OccultaBundle.Mode
    let ephemeralPublicKey: Data
    /// It opened through the bootstrap layer, not the ordinary hybrid key.
    let wasBootstrap: Bool
    /// Carol: the full material her first Bob message gave her. Nil otherwise.
    let derivedQuantum: QuantumKeyMaterial?
}

extension Manager.Crypto {

    /// The slot's key source: the ECDH output and the two public keys it was made with.
    private struct CardSlotSource {
        let ecdhOutput: Data
        let own: Data
        let peer: Data
        let used: InboundPrekeyUse
    }

    /// Finds our slot in a card conversation's bundle by trial, as `openRecipientSlot` does for an ordinary one.
    ///
    /// Per slot, in order: a prekey of ours that `prekeyID` names (one-time, then last-resort); else, for a
    /// forward-secret slot naming none, our card agreement key (Carol's slots to Bob); long-term slots use the two
    /// card agreement keys. Then the ordinary hybrid key if we hold the material, then the bootstrap layer
    /// (SPEC §4.3 "Opening").
    ///
    /// The prekey of an opened slot is consumed on every exit, exactly as `openRecipientSlot` consumes it, except
    /// when the body doesn't match the slot's digest. A card sender always sends the digest and always signs a
    /// forward-secret slot, so a missing one is refused rather than allowed by tier.
    func openCardSlot(
        in bundle: OccultaBundle,
        blind: Data,
        senderContactID: String,
        card: CardReceiveContext,
        prekeys: PrekeyPrivateKeys,
        body: BundleBody? = nil
    ) throws -> CardSlotOpening {
        let body = body ?? .inline(bundle)
        guard let recipients = bundle.group?.recipients else { throw GroupDecryptError.noGroupEnvelope }
        guard recipients.count <= Group.slotCount else { throw GroupDecryptError.tooManyRecipients }

        var usedPrekey: Prekey?
        defer {
            if let usedPrekey { prekeys.consume(prekeyID: usedPrekey.id, contactID: usedPrekey.contactID) }
        }

        for entry in recipients {
            guard
                let source = self.cardSlotSource(entry.secrecyContext, senderContactID: senderContactID, card: card, prekeys: prekeys),
                let opened = self.openCardEntry(entry, source: source, blind: blind, card: card)
            else { continue }

            guard let bodyDigest = opened.payload.bodyDigest else { throw GroupDecryptError.missingBodyDigest }
            guard bodyDigest == (try body.digest()) else { throw GroupDecryptError.bodyDigestMismatch }

            // As in `openRecipientSlot`: the outer header is authenticated only by this open (Bug 181).
            try body.authenticateHeader(sessionKey: SymmetricKey(data: opened.payload.sessionKey))

            usedPrekey = source.used.consumable

            if entry.secrecyContext.mode == .forwardSecret {
                guard let signature = opened.payload.senderEphemeralSignature else {
                    throw GroupDecryptError.missingSenderEphemeralSignature
                }
                guard self.verifySenderEphemeralSignature(
                    signature, ephemeralPublicKey: entry.secrecyContext.ephemeralPublicKey,
                    senderPublicKey: card.peerSigningKey, acceptsBareForm: false
                ) else { throw GroupDecryptError.senderEphemeralSignatureMismatch }
            }
            return CardSlotOpening(
                payload: opened.payload, used: source.used, mode: entry.secrecyContext.mode,
                ephemeralPublicKey: entry.secrecyContext.ephemeralPublicKey,
                wasBootstrap: opened.wasBootstrap, derivedQuantum: opened.derivedQuantum
            )
        }
        throw GroupDecryptError.recipientSlotNotFound
    }

    private func cardSlotSource(
        _ secrecy: OccultaBundle.SecrecyContext,
        senderContactID: String,
        card: CardReceiveContext,
        prekeys: PrekeyPrivateKeys
    ) -> CardSlotSource? {
        switch secrecy.mode {
        case .forwardSecret:
            guard let prekeyID = secrecy.prekeyID, secrecy.ephemeralPublicKey.count == 65 else { return nil }
            let temp = Prekey(id: prekeyID, contactID: senderContactID, publicKey: Data())

            if let key = prekeys.privateKey(forPrekeyID: prekeyID, contactID: senderContactID) {
                return Self.enclaveSource(key, ephemeralPublicKey: secrecy.ephemeralPublicKey, used: .oneTime(temp))
            }
            if let (keyID, key) = prekeys.lastResortKey(forPrekeyID: prekeyID, ephemeralPublicKey: secrecy.ephemeralPublicKey) {
                return Self.enclaveSource(key, ephemeralPublicKey: secrecy.ephemeralPublicKey, used: .lastResort(keyID: keyID))
            }
            // Names none of our prekeys: Carol's slot to the card agreement key.
            guard let raw = try? card.keys.sharedSecret(agreementBlob: card.agreementBlob, peerPublicKey: secrecy.ephemeralPublicKey) else {
                return nil
            }
            return CardSlotSource(ecdhOutput: Self.cardECDHOutput(raw), own: card.ownAgreementKey, peer: secrecy.ephemeralPublicKey, used: .longTerm)

        case .longTermFallback:
            guard let raw = try? card.keys.sharedSecret(agreementBlob: card.agreementBlob, peerPublicKey: card.peerAgreementKey) else {
                return nil
            }
            return CardSlotSource(ecdhOutput: Self.cardECDHOutput(raw), own: card.ownAgreementKey, peer: card.peerAgreementKey, used: .longTerm)

        default:
            return nil
        }
    }

    /// The prekey side of a forward-secret slot. Card conversations only ever have record-held (Enclave) prekeys.
    private static func enclaveSource(_ key: PrekeyPrivateKey, ephemeralPublicKey: Data, used: InboundPrekeyUse) -> CardSlotSource? {
        guard
            case .enclave(let enclaveKey) = key,
            let peer = try? P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublicKey),
            let secret = try? enclaveKey.sharedSecretFromKeyAgreement(with: peer)
        else { return nil }
        let ecdhOutput = secret.x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: Data(), outputByteCount: 32)
            .withUnsafeBytes { Data($0) }
        return CardSlotSource(ecdhOutput: ecdhOutput, own: enclaveKey.publicKey.x963Representation, peer: ephemeralPublicKey, used: used)
    }

    private func openCardEntry(
        _ entry: OccultaBundle.Recipient,
        source: CardSlotSource,
        blind: Data,
        card: CardReceiveContext
    ) -> (payload: OccultaBundle.RecipientPayload, wasBootstrap: Bool, derivedQuantum: QuantumKeyMaterial?)? {
        let isLongTerm = entry.secrecyContext.mode == .longTermFallback

        // The ordinary hybrid key, if we hold the material.
        if let quantum = card.quantum {
            let key = isLongTerm
                ? Self.cardLongTermKey(ecdhOutput: source.ecdhOutput, ownPublicKey: source.own, peerPublicKey: source.peer, quantumMaterial: quantum)
                : Manager.Key.forwardSecretSessionKey(ecdhOutput: source.ecdhOutput, ownPublicKey: source.own, peerMaterial: source.peer, quantumMaterial: quantum)
            if let key, let payload = Self.openPayload(entry.wrappedPayload, key: key, blind: blind) {
                return (payload, false, nil)
            }
        }

        // The bootstrap layer.
        guard
            let outerKey = Manager.Key.forwardSecretSessionKey(
                ecdhOutput: source.ecdhOutput, ownPublicKey: source.own, peerMaterial: source.peer, quantumMaterial: nil
            ),
            let layer = try? CardBootstrap.openOuter(entry.wrappedPayload, outerKey: outerKey, blind: blind)
        else { return nil }

        let innerKey: SymmetricKey?
        var derived: QuantumKeyMaterial?
        switch card.role {
        case .bob:
            innerKey = card.quantum.flatMap {
                CardBootstrap.carolInnerKey(
                    ecdhOutput: source.ecdhOutput, ownPublicKey: source.own, peerPublicKey: source.peer, ss1: $0.decapsulatedSecret
                )
            }
        case .carol:
            let quantum: QuantumKeyMaterial?
            if let held = card.quantum {
                quantum = held
            } else if let pending = card.pending, let ss2 = pending.postQuantum.decapsulate(ciphertext: layer.mlkemCiphertext, keyBlob: pending.mlkemBlob) {
                quantum = QuantumKeyMaterial(
                    encapsulatedSecret: pending.ss1, decapsulatedSecret: ss2,
                    ourCiphertext: pending.ct1, peerCiphertext: layer.mlkemCiphertext
                )
                derived = quantum
            } else {
                quantum = nil
            }
            innerKey = quantum.flatMap {
                Manager.Key.forwardSecretSessionKey(
                    ecdhOutput: source.ecdhOutput, ownPublicKey: source.own, peerMaterial: source.peer, quantumMaterial: $0
                )
            }
        }

        guard
            let innerKey,
            let plain = try? CardBootstrap.openInner(layer.inner, mlkemCiphertext: layer.mlkemCiphertext, innerKey: innerKey, blind: blind),
            let payload = try? JSONDecoder().decode(OccultaBundle.RecipientPayload.self, from: plain)
        else { return nil }
        return (payload, true, derived)
    }

    private static func openPayload(_ wrapped: Data, key: SymmetricKey, blind: Data) -> OccultaBundle.RecipientPayload? {
        guard
            let box = try? AES.GCM.SealedBox(combined: wrapped),
            let plain = try? AES.GCM.open(box, using: key, authenticating: blind)
        else { return nil }
        return try? JSONDecoder().decode(OccultaBundle.RecipientPayload.self, from: plain)
    }
}

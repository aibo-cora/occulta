//
//  PairingOffer.swift
//  Occulta
//
//  What a key exchange hands to `save()` for a pair-key pairing (`bugs.md` Bug 196): our first prekeys as a scratch
//  record, the pair keys we made and the batch and pair keys the peer sent, the nonces both sides committed to, and the
//  pair-key ECDH. Present only when both phones sent a `pairing` field, which is also the signal that both can hold a
//  routing key and pair keys: a 2.0.0 phone sends none.
//

import Foundation
import CryptoKit
import OccultaFormats

nonisolated
struct PairingOffer: Equatable {

    /// Our nonce and the peer's, from the discovery messages. A classical exchange has them too, with a peer that
    /// sends one.
    let ourNonce: Data
    let peerNonce: Data

    /// The record we'll hold for this peer: one pending batch of our keys, Enclave blobs kept in memory only until
    /// `save()` installs them. An exchange that is abandoned leaves nothing behind: CryptoKit Enclave keys have no
    /// keychain item.
    let ownPrekeys: PrekeyRecord

    /// The batch the peer sent in its identity message, as received.
    let peerBatch: Batch

    /// The pair keys we made for this pairing, and what the peer sent of theirs.
    let ours: OwnPairKeys
    let theirs: PeerPairKeys

    /// The ECDH output between the two agreement keys (X9.63 KDF applied), made when the offer is assembled so the
    /// Enclave blob is used once, by the exchange, and not again by the screens that follow.
    let pairwiseECDH: Data

    struct Batch: Equatable {
        let id: Data?
        let generatedAt: Date
        let prekeys: [OccultaBundle.WirePrekey]
        let lastResort: OccultaBundle.WirePrekey?

        init(_ wire: OccultaBundle.SealedPayload.PrekeySyncBatch) {
            self.id          = wire.id
            self.generatedAt = wire.generatedAt
            self.prekeys     = wire.prekeys
            self.lastResort  = wire.lastResort
        }
    }

    /// The two Enclave keys one exchange made for us, and an ML-DSA-87 key where the phone could make one.
    struct OwnPairKeys: Equatable {
        let agreementBlob: Data
        let agreementKey: Data
        let signingBlob: Data
        let signingKey: Data
        let mldsaBlob: Data?
        let mldsaKey: Data?
    }

    /// The public keys the peer sent, validated.
    struct PeerPairKeys: Equatable {
        let agreementKey: Data
        let signingKey: Data
        let mldsaKey: Data?
    }

    /// What each phone sent, as `RoutingKey.transcript` takes it.
    var ourBlock: RoutingKey.PairBlock? {
        RoutingKey.PairBlock(agreementKey: self.ours.agreementKey, signingKey: self.ours.signingKey, mldsaKey: self.ours.mldsaKey)
    }
    var theirBlock: RoutingKey.PairBlock? {
        RoutingKey.PairBlock(agreementKey: self.theirs.agreementKey, signingKey: self.theirs.signingKey, mldsaKey: self.theirs.mldsaKey)
    }

    /// Both phones' transcript. `nil` only for a block that does not validate, which `accepted` has already refused.
    var transcript: Data? {
        guard let ours = self.ourBlock, let theirs = self.theirBlock else { return nil }
        return RoutingKey.transcript(ours, theirs)
    }

    /// The routing key this pairing holds, from the pair-key ECDH, the identity ECDH made inside `keyManager`, the ML-KEM
    /// secrets where the exchange had them and both nonces. Both phones get the same bytes. `nil` if anything is missing
    /// or the key manager couldn't derive it, in which case nothing is saved.
    func routingKey(withPeer peerIdentity: Data, quantum: QuantumKeyMaterial?, using keyManager: any KeyManagerProtocol) -> Data? {
        guard let transcript = self.transcript else { return nil }
        return keyManager.createRoutingKey(
            peerP256Material: peerIdentity, pairwiseECDH: self.pairwiseECDH, ourAgreementKey: self.ours.agreementKey,
            peerAgreementKey: self.theirs.agreementKey, transcript: transcript, quantumMaterial: quantum,
            ourNonce: self.ourNonce, peerNonce: self.peerNonce
        )
    }

    /// The key the verification words come from. It covers both pair blocks, so a pair key or an ML-DSA key a man in the
    /// middle added, removed or swapped changes the words.
    func wordsKey(withPeer peerIdentity: Data, quantum: QuantumKeyMaterial?, using keyManager: any KeyManagerProtocol) -> Data? {
        guard let transcript = self.transcript else { return nil }
        return keyManager.createPairwiseDicewareKey(
            peerP256Material: peerIdentity, pairwiseECDH: self.pairwiseECDH, transcript: transcript, quantumMaterial: quantum,
            ourNonce: self.ourNonce, peerNonce: self.peerNonce
        )?.withUnsafeBytes { Data($0) }
    }

    /// What `save()` seals into the key row.
    var pairKeys: PairKeys {
        PairKeys(
            ourAgreementBlob: self.ours.agreementBlob, ourAgreementKey: self.ours.agreementKey,
            ourSigningBlob: self.ours.signingBlob, ourSigningKey: self.ours.signingKey,
            peerAgreementKey: self.theirs.agreementKey, peerSigningKey: self.theirs.signingKey,
            ourMLDSABlob: self.ours.mldsaBlob, peerMLDSAKey: self.theirs.mldsaKey
        )
    }

    /// Our pending batch in wire form: what the identity message carries.
    static func wireBatch(of record: PrekeyRecord) -> OccultaBundle.SealedPayload.PrekeySyncBatch? {
        PrekeyBookkeeper().pendingBatch(in: record, publicKeyOfBlob: Manager.PrekeySecretsManager.publicKey(ofBlob:)).map {
            OccultaBundle.SealedPayload.PrekeySyncBatch(
                generatedAt: $0.generatedAt, prekeys: $0.prekeys, id: $0.id, lastResort: $0.lastResort
            )
        }
    }
}

// MARK: - What goes on the wire

extension PairingOffer {

    /// The `pairing` field of our identity message, or `nil` if there is nothing to send.
    static func field(prekeys: PrekeyRecord?, keys: OwnPairKeys?) -> Exchange.PairingField? {
        guard let prekeys, let keys, let batch = Self.wireBatch(of: prekeys) else { return nil }
        return Exchange.PairingField(
            prekeyBatch: batch, agreementKey: keys.agreementKey, signingKey: keys.signingKey, mldsaKey: keys.mldsaKey
        )
    }

    /// What the peer's `pairing` field comes to, or `nil` if it is not one we can use, in which case the pairing is made
    /// without pair keys and the two phones' words differ, which is on the screen. Refused: a key that is the wrong size
    /// or not a point on the curve, two keys that are the same, a key equal to either phone's identity key, and a key
    /// equal to one of ours (a reflection). A malformed ML-DSA key alone is dropped and the P-256 pair stays.
    ///
    /// Never checked against other contacts' keys: a refusal that depended on a hidden contact would reveal it.
    static func accepted(
        _ field: Exchange.PairingField, ours: OwnPairKeys, ourIdentity: Data?, peerIdentity: Data,
        isPoint: (Data) -> Bool = PairingOffer.isP256Point
    ) -> (batch: Batch, keys: PeerPairKeys)? {
        let agreement = field.agreementKey, signing = field.signingKey
        guard isPoint(agreement), isPoint(signing) else { return nil }

        var forbidden: Set<Data> = [peerIdentity, ours.agreementKey, ours.signingKey]
        if let ourIdentity { forbidden.insert(ourIdentity) }
        guard !forbidden.contains(agreement), !forbidden.contains(signing) else { return nil }

        // A block validates the lengths and that the two P-256 keys differ; the ML-DSA key is checked on its own so a bad
        // one doesn't cost the pair.
        guard RoutingKey.PairBlock(agreementKey: agreement, signingKey: signing) != nil else { return nil }
        let mldsa = field.mldsaKey.flatMap {
            RoutingKey.PairBlock(agreementKey: agreement, signingKey: signing, mldsaKey: $0) == nil ? nil : $0
        }
        return (Batch(field.prekeyBatch), PeerPairKeys(agreementKey: agreement, signingKey: signing, mldsaKey: mldsa))
    }

    /// Whether `key` is a 65-byte X9.63 point on P-256.
    static func isP256Point(_ key: Data) -> Bool {
        key.count == 65 && (try? P256.KeyAgreement.PublicKey(x963Representation: key)) != nil
    }
}

// MARK: - What we make

extension PairingOffer {

    /// A scratch record holding one fresh pending batch: the batch size's one-time keys and a last-resort key, all
    /// made in the Enclave, the same as `ContactManager.installFreshBatch(into:)` makes for a contact.
    @MainActor
    static func makeOwnPrekeys(now: Date = Date()) throws -> PrekeyRecord {
        let batchSize = Manager.PrekeySecretsManager.defaultBatchSize
        let blobs = try Manager.PrekeySecretsManager().generateEnclaveKeys(count: batchSize + 1)
        var record = PrekeyRecord.empty
        PrekeyBookkeeper().install(Array(blobs.prefix(batchSize)), lastResort: blobs[batchSize], into: &record, now: now)
        return record
    }

    /// Our two P-256 pair keys and, where the phone can make one, an ML-DSA-87 key. A failure to make either P-256 key
    /// throws: a phone sends all of the `pairing` field or none. An ML-DSA key that can't be made, or whose blob would
    /// not fit its room in the sealed column, is left out: the pair stands without it.
    static func makeOwnPairKeys(using provider: any CardKeyProviding) throws -> OwnPairKeys {
        let agreement = try provider.makeAgreementKey()
        let signing = try provider.makeSigningKey()
        // A blob that would not fit its room in the sealed column is found here, where it costs no pairing, and not at Save,
        // where it would fail an exchange both people sat through. A phone that makes such blobs sends no `pairing` field.
        guard agreement.blob.count <= PairingCodec.p256BlobRoom, signing.blob.count <= PairingCodec.p256BlobRoom else {
            throw PairingCodec.CodecError.wrongSize
        }
        let mldsa = try? provider.makeMLDSAKey()
        let fits = mldsa.map { $0.blob.count <= PairingCodec.mldsaBlobRoom && $0.publicKey.count == PairingCodec.mldsaKeySize } ?? false
        return OwnPairKeys(
            agreementBlob: agreement.blob, agreementKey: agreement.publicKey,
            signingBlob: signing.blob, signingKey: signing.publicKey,
            mldsaBlob: fits ? mldsa?.blob : nil, mldsaKey: fits ? mldsa?.publicKey : nil
        )
    }

    /// The pair-key ECDH output, as `.ecdhKeyExchangeCofactorX963SHA256` gives it.
    @MainActor
    static func pairwiseECDH(
        ours: OwnPairKeys, peerAgreementKey: Data, using provider: any CardKeyProviding
    ) throws -> Data {
        Manager.Crypto.cardECDHOutput(try provider.sharedSecret(agreementBlob: ours.agreementBlob, peerPublicKey: peerAgreementKey))
    }
}

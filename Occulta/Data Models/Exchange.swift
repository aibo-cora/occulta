//
//  Exchange.swift
//  Occulta
//
//  Updated for hybrid post-quantum key exchange.
//
//  ⚠️ Backward compatibility: the version field stays `.v1` on the wire.
//  A v1 peer's decoder only has `case v1 = 1` in its enum — sending any
//  other raw value causes a DecodingError and silently kills the exchange.
//  PQ capability is negotiated implicitly via the presence of optional fields
//  (`nonce`, `encapsulationKey`, `ciphertext`). V1 decoders ignore unknown keys.
//

import Foundation
import OccultaFormats

struct Exchange: Codable {
    let id: String
    let token: Data
    let version: Version

    let identity: Data?
    let nonce: Data?
    let encapsulationKey: Data?
    let ciphertext: Data?
    /// The meeting-check proof (`Docs/Features/Introduction Cards/SPEC.md` §7): 64 bytes, a signature or random
    /// filler, with an empty `token` and nothing else. An older build's decoder ignores the key and reads this as a
    /// discovery message, whose empty token fails to unarchive, so the message is dropped harmlessly.
    let cardProof: Data?
    /// What a pair-key pairing needs from this phone, in the identity message (`bugs.md` Bug 196): our first prekeys and
    /// our pair keys. Its presence is the signal that this phone can hold a routing key and pair keys, so a phone that
    /// sends none is treated as one that can't. It is one field so there is one capability bit: a phone sends all of it
    /// or none. An older build's decoder ignores the key. `nil` in every other message.
    let pairing: PairingField?
    /// `ExchangeCommitment.commitment(to:)` of the sender's nonce, in the discovery message in place of `nonce` (Bug 198).
    /// Its presence is the signal that the sender commits before it reveals; a discovery message with a `nonce` and no
    /// commitment is an older build's, whose nonce is in the clear. An older build's decoder ignores the key.
    let nonceCommitment: Data?
    /// The nonce a commitment was made to, 16 bytes, sent last in the exchange, initiator first, with an empty `token` and
    /// nothing else. Sent only to a peer that sent a commitment, so an older build never receives one (its decoder would
    /// read it as a discovery message with an empty token and drop it).
    let revealedNonce: Data?

    init(
        id: String,
        token: Data,
        version: Version = .v1,
        identity: Data? = nil,
        nonce: Data? = nil,
        encapsulationKey: Data? = nil,
        ciphertext: Data? = nil,
        cardProof: Data? = nil,
        pairing: PairingField? = nil,
        nonceCommitment: Data? = nil,
        revealedNonce: Data? = nil
    ) {
        self.id = id
        self.token = token
        self.version = version
        self.identity = identity
        self.nonce = nonce
        self.encapsulationKey = encapsulationKey
        self.ciphertext = ciphertext
        self.cardProof = cardProof
        self.pairing = pairing
        self.nonceCommitment = nonceCommitment
        self.revealedNonce = revealedNonce
    }

    /// The `pairing` field of an identity message.
    struct PairingField: Codable {
        /// 15 one-time keys and a last-resort key.
        let prekeyBatch: OccultaBundle.SealedPayload.PrekeySyncBatch
        /// X9.63, 65 bytes: the pair's agreement key and its signing key.
        let agreementKey: Data
        let signingKey: Data
        /// An ML-DSA-87 public key (2,592 bytes), from a phone that could make one. Nothing signs with it in 2.0.1.
        let mldsaKey: Data?
    }

    enum Version: Int8, Codable {
        case v1 = 1
        /// ⚠️ Do NOT send on the wire until v1 decoders are no longer in the field.
        case v2pq = 2
    }

    /// Checked before `isDiscovery` in routing: a proof has no identity and no ciphertext either.
    var isCardProof: Bool { cardProof != nil }
    /// Checked before `isDiscovery` too, for the same reason.
    var isNonceReveal: Bool { revealedNonce != nil && identity == nil && ciphertext == nil && cardProof == nil }
    var isDiscovery: Bool { identity == nil && ciphertext == nil && cardProof == nil && revealedNonce == nil }
    var isIdentity: Bool { identity != nil && ciphertext == nil }
    var isCiphertext: Bool { ciphertext != nil }
    var supportsPQ: Bool { encapsulationKey != nil }
}

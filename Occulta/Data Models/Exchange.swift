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

    init(
        id: String,
        token: Data,
        version: Version = .v1,
        identity: Data? = nil,
        nonce: Data? = nil,
        encapsulationKey: Data? = nil,
        ciphertext: Data? = nil,
        cardProof: Data? = nil,
        pairing: PairingField? = nil
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
    var isDiscovery: Bool { identity == nil && ciphertext == nil && cardProof == nil }
    var isIdentity: Bool { identity != nil && ciphertext == nil }
    var isCiphertext: Bool { ciphertext != nil }
    var supportsPQ: Bool { encapsulationKey != nil }
}

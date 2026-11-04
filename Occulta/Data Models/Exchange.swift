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
    /// Our first prekeys, in the identity message: 15 one-time keys and a last-resort key (`bugs.md` Bug 196). Its
    /// presence is the signal that this phone can hold a routing key, so a phone that sends none is treated as one
    /// that can't. An older build's decoder ignores the key. `nil` in every other message.
    let prekeyBatch: OccultaBundle.SealedPayload.PrekeySyncBatch?

    init(
        id: String,
        token: Data,
        version: Version = .v1,
        identity: Data? = nil,
        nonce: Data? = nil,
        encapsulationKey: Data? = nil,
        ciphertext: Data? = nil,
        cardProof: Data? = nil,
        prekeyBatch: OccultaBundle.SealedPayload.PrekeySyncBatch? = nil
    ) {
        self.id = id
        self.token = token
        self.version = version
        self.identity = identity
        self.nonce = nonce
        self.encapsulationKey = encapsulationKey
        self.ciphertext = ciphertext
        self.cardProof = cardProof
        self.prekeyBatch = prekeyBatch
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

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

struct Exchange: Codable {
    let id: String
    let token: Data
    let version: Version

    let identity: Data?
    let nonce: Data?
    let encapsulationKey: Data?
    let ciphertext: Data?

    init(
        id: String,
        token: Data,
        version: Version = .v1,
        identity: Data? = nil,
        nonce: Data? = nil,
        encapsulationKey: Data? = nil,
        ciphertext: Data? = nil
    ) {
        self.id = id
        self.token = token
        self.version = version
        self.identity = identity
        self.nonce = nonce
        self.encapsulationKey = encapsulationKey
        self.ciphertext = ciphertext
    }

    enum Version: Int8, Codable {
        case v1 = 1
        /// ⚠️ Do NOT send on the wire until v1 decoders are no longer in the field.
        case v2pq = 2
    }

    var isDiscovery: Bool { identity == nil && ciphertext == nil }
    var isIdentity: Bool { identity != nil && ciphertext == nil }
    var isCiphertext: Bool { ciphertext != nil }
    var supportsPQ: Bool { encapsulationKey != nil }
}

//
//  PairingState.swift
//  Occulta
//
//  What a pairing holds (`bugs.md` Bug 196): the routing key both phones derived at the exchange and, for a pairing made
//  with a peer that sent pair keys, the keys of the pair. Data only: `PairingCodec` stores it, and
//  `ContactManager+Pairing` reads and writes it on the contact's `Key` row.
//

import Foundation

/// The two Enclave keys one pairing owns, an ML-DSA-87 key where the phone could make one, and what the peer sent.
///
/// Private halves are Secure Enclave blobs: CryptoKit's Enclave keys create no keychain item, so a keychain listing says
/// nothing about how many pairings exist, and overwriting the sealed column deletes them.
nonisolated
struct PairKeys: Equatable {

    /// The agreement key's Enclave blob and X9.63 public key.
    var ourAgreementBlob: Data
    var ourAgreementKey: Data
    /// The signing key's Enclave blob and X9.63 public key.
    var ourSigningBlob: Data
    var ourSigningKey: Data
    /// The peer's two public keys, as they sent them.
    var peerAgreementKey: Data
    var peerSigningKey: Data
    /// Our ML-DSA-87 Enclave blob, from a phone that could make one. Nothing signs with it in 2.0.1.
    var ourMLDSABlob: Data?
    /// The peer's ML-DSA-87 public key, if they sent one.
    var peerMLDSAKey: Data?
}

/// The routing key one pairing holds, or none, and its pair keys.
///
/// Sealed on `Contact.Profile.Key` because a routing key belongs to the peer key it was made with: a key change leaves
/// the old one on the retired row, and nothing has to remember to drop it.
///
/// A pairing is made with its routing key at the exchange, with a peer that made it too, or it never has one: there is no
/// way to give an existing pairing one afterwards, so the state never changes once written.
nonisolated
struct PairingState: Equatable {

    /// The routing key, once the exchange made it. `nil` for a pairing from before this fix, or with a peer that can't
    /// make one. Also what every such row holds as filler, so the column says nothing about which rows have one.
    var routingKey: Data?

    /// The pair keys of a pairing made with a peer that sent its own. Only ever present with a routing key.
    var keys: PairKeys?

    static let empty = PairingState(routingKey: nil, keys: nil)

    /// A pairing that derived its routing key at the exchange, without pair keys.
    static func derived(secret: Data) -> PairingState {
        PairingState(routingKey: secret, keys: nil)
    }

    /// A pairing that derived its routing key from a pair of keys.
    static func paired(routingKey: Data, keys: PairKeys) -> PairingState {
        PairingState(routingKey: routingKey, keys: keys)
    }

    /// Whether this pairing refuses an old-form file (the sender named by identity fingerprint): otherwise an old-form
    /// file from the person's other pairing matches it, which is the bug. A pairing without a routing key keeps accepting
    /// old form.
    var refusesOldForm: Bool { self.routingKey != nil }

    /// Whether files to this peer go in the routing-key form: the pairing holds the key, and the peer made it too.
    var sendsNewForm: Bool { self.routingKey != nil }

    /// The routing key, once held. Routing tags are accepted from this point.
    var secret: Data? { self.routingKey }
}

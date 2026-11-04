//
//  PairingSecretState.swift
//  Occulta
//
//  What a pairing holds for its secret (`bugs.md` Bug 196). Data only: `PairingSecretCodec` stores it, and
//  `ContactManager+PairingSecret` reads and writes it on the contact's `Key` row.
//

import Foundation

/// The secret one pairing holds, or none.
///
/// Sealed on `Contact.Profile.Key` because a secret belongs to the peer key it was made with: a key change leaves
/// the old secret on the retired row, and nothing has to remember to drop it.
///
/// A pairing is made with its secret at the exchange, with a peer that made it too, or it never has one: there is no way
/// to give an existing pairing a secret afterwards, so the state never changes once written.
nonisolated
struct PairingSecretState: Equatable {

    /// The secret, once the exchange made it. `nil` for a pairing from before this fix, or with a peer that can't make
    /// one. Also what every such row holds as filler, so the column says nothing about which rows have a secret.
    var secret: Data?

    static let empty = PairingSecretState(secret: nil)

    /// A pairing that derived its secret at the exchange, with a peer that did the same.
    static func derived(secret: Data) -> PairingSecretState {
        PairingSecretState(secret: secret)
    }

    /// Whether this pairing refuses an old-form file (the sender named by identity fingerprint): otherwise an old-form
    /// file from the person's other pairing matches it, which is the bug. A pairing without a secret keeps accepting old form.
    var refusesOldForm: Bool { self.secret != nil }

    /// Whether files to this peer go in the pairing-secret form: the pairing holds the secret, and the peer made it too.
    var sendsNewForm: Bool { self.secret != nil }
}

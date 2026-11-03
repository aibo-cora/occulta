//
//  PairingSecretState.swift
//  Occulta
//
//  Where a pairing stands on its secret (`bugs.md` Bug 196). Data only: `PairingSecretCodec` stores it, and
//  `ContactManager+PairingSecret` reads and writes it on the contact's `Key` row.
//

import Foundation

/// The secret one pairing holds, or how far it is from holding one.
///
/// Sealed on `Contact.Profile.Key` because a secret belongs to the peer key it was made with: a key change leaves
/// the old secret on the retired row, and nothing has to remember to drop it.
nonisolated
struct PairingSecretState: Equatable {

    enum Phase: Equatable {
        /// No secret: a pairing from before this fix, or with a peer that can't hold one. Also the filler every
        /// row holds, so the column says nothing about which rows have a secret.
        case none
        /// Our half is made and saved (before its first send, so a crash retries the same half), and we are
        /// waiting for the peer's. A peer's half that arrives first goes straight to `held`: no peer half is stored.
        case swapping(ourHalf: Data)
        /// Both sides made the secret: derived at the pairing, or from two halves. `peerConfirmed` once the peer has
        /// shown it holds it.
        case held(secret: Data, peerConfirmed: Bool)
    }

    var phase: Phase

    /// Set for a pairing that began with a secret, and never cleared. A record that has it refuses an old-form file
    /// (the sender named by identity fingerprint), because otherwise an old-form file from the person's other
    /// pairing matches it, which is the bug. A record without it keeps accepting old form, so a file sent before
    /// the swap finished is not lost when it arrives after.
    var refusesOldForm: Bool

    static let empty = PairingSecretState(phase: .none, refusesOldForm: false)

    /// A pairing that derived its secret at the exchange, with a peer that did the same: confirmed from the start.
    static func derived(secret: Data) -> PairingSecretState {
        PairingSecretState(phase: .held(secret: secret, peerConfirmed: true), refusesOldForm: true)
    }

    /// The secret, once held. Routing tags are accepted from this point.
    var secret: Data? {
        if case .held(let secret, _) = self.phase { return secret }
        return nil
    }

    /// Whether files to this peer go in the pairing-secret form: we hold the secret and know they do.
    var sendsNewForm: Bool {
        if case .held(_, true) = self.phase { return true }
        return false
    }
}

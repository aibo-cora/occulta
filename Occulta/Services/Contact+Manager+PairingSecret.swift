//
//  Contact+Manager+PairingSecret.swift
//  Occulta
//
//  ContactManager's side of the per-pairing secret (`bugs.md` Bug 196): the only code that reads or writes a peer
//  key's `PairingSecretState`. The format is `PairingSecretCodec`'s; this file seals, opens and stores.
//

import Foundation

extension ContactManager {

    enum PairingSecretStoreError: Error, Equatable {
        case sealFailed
    }

    /// The state sealed on `key`. A row without one, or whose seal won't open, reads as empty: the migration fills
    /// the first, and an unreadable state can only mean no secret we could use.
    func pairingSecretState(of key: Contact.Profile.Key) -> PairingSecretState {
        guard
            let sealed = key.pairingSecretEncrypted,
            let plaintext = sealed.decrypt(),
            let state = try? PairingSecretCodec().decode(plaintext)
        else { return .empty }
        return state
    }

    /// Seals `state` into `key`. Doesn't save; the caller does.
    func store(_ state: PairingSecretState, in key: Contact.Profile.Key) throws {
        guard let sealed = try PairingSecretCodec().encode(state).encrypt() else {
            throw PairingSecretStoreError.sealFailed
        }
        key.pairingSecretEncrypted = sealed
    }

    /// The sealed form of `state`, for a row not yet inserted.
    func sealedPairingSecret(_ state: PairingSecretState) throws -> Data {
        guard let sealed = try PairingSecretCodec().encode(state).encrypt() else {
            throw PairingSecretStoreError.sealFailed
        }
        return sealed
    }

    /// The state on `contact`'s current key: the latest one not expired, the key every send and receive uses.
    func pairingSecretState(for contact: Contact.Profile) -> PairingSecretState {
        guard let key = contact.contactPublicKeys?.last(where: { $0.expiredOn == nil }) else { return .empty }
        return self.pairingSecretState(of: key)
    }
}

//
//  Contact+Manager+PairingSecret.swift
//  Occulta
//
//  ContactManager's side of the per-pairing secret (`bugs.md` Bug 196): the only code that reads or writes a peer
//  key's `PairingSecretState`. The format is `PairingSecretCodec`'s; this file seals, opens and stores.
//

import Foundation
import OccultaFormats

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

    // MARK: - The first prekeys of a pairing

    /// Installs a pairing's first prekeys into `contact`'s record and records the peer at the pairing-secret tier.
    /// Doesn't save; the caller does, in the same save as the key row.
    ///
    /// Our batch goes in pending as it was sent, so it keeps travelling until the peer uses a key from it, and the peer's
    /// is accepted through the bookkeeper's rules. A peer batch outside the record's limits, which no build of ours
    /// produces, is dropped and the pairing goes on with only our side. Everything else the record held of an earlier
    /// pairing is retired (`PrekeyBookkeeper.startPairing`).
    ///
    /// The peer sent a batch, so it runs 2.0.1 or later: the tier is recorded now, which lets the first message be
    /// sent in the group format, and in the pairing-secret form once stage 5's gate allows.
    func installPairingPrekeys(_ pairing: PairingOffer, in contact: Contact.Profile) throws {
        guard let ownBatch = pairing.ownPrekeys.ownBatches.first(where: \.isPending) else { return }

        var record = try self.prekeyRecord(for: contact)
        let bookkeeper = PrekeyBookkeeper()
        bookkeeper.startPairing(with: ownBatch, in: &record, now: Date())
        let theirs = pairing.peerBatch
        _ = try? bookkeeper.accept(
            id: theirs.id, generatedAt: theirs.generatedAt, prekeys: theirs.prekeys, lastResort: theirs.lastResort,
            onReopenableSlot: false, into: &record
        )
        try self.store(record, for: contact)

        if let byte = OccultaBundle.Version.pairingSecretCapable.wireByte {
            contact.maxBundleVersion = try Manager.Crypto().encrypt(data: Data([byte]))
        }
    }
}

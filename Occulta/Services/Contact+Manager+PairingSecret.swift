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

    // MARK: - Sending and receiving (stage 5)

    /// The secret to seal a file to `contact` with, or nil: the pairing holds one, the peer is known to hold it too, and
    /// the peer is at the pairing-secret tier. Anything less sends as before.
    func pairingSecretForSending(to contact: Contact.Profile, tier: OccultaBundle.Version) -> Data? {
        guard tier.isAtLeast(.pairingSecretCapable) else { return nil }
        let state = self.pairingSecretState(for: contact)
        return state.sendsNewForm ? state.secret : nil
    }

    /// What a pairing contributes to opening a file from `contact`: its secret, once held, and whether an old-form file
    /// may still be tried against it. nil when there is no secret to route by.
    func pairingSlotContext(for contact: Contact.Profile) -> Manager.Crypto.PairingSlotContext? {
        let state = self.pairingSecretState(for: contact)
        return state.secret.map { Manager.Crypto.PairingSlotContext(secret: $0, acceptsOldForm: !state.refusesOldForm) }
    }

    /// Whether `bundle` names `contact` as its sender by a pairing routing tag: some slot carries
    /// `PairingSecret.routingTag(secret, bundle.fingerprintNonce)` for the secret `contact` holds.
    func bundleCarriesRoutingTag(of contact: Contact.Profile, in bundle: OccultaBundle) -> Bool {
        guard let secret = self.pairingSecretState(for: contact).secret, let recipients = bundle.group?.recipients else {
            return false
        }
        let tag = PairingSecret.routingTag(secret: secret, nonce: bundle.fingerprintNonce)
        return recipients.contains { $0.routingTag == tag }
    }

    /// Whether an old-form file (the sender named by identity fingerprint) may be attributed to `contact`. Not once the
    /// pairing began with a secret: such a file is another pairing's (Bug 196).
    func acceptsOldForm(from contact: Contact.Profile) -> Bool {
        !self.pairingSecretState(for: contact).refusesOldForm
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

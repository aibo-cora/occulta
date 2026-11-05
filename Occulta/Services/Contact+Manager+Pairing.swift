//
//  Contact+Manager+Pairing.swift
//  Occulta
//
//  ContactManager's side of the per-routing key (`bugs.md` Bug 196): the only code that reads or writes a peer
//  key's `PairingState`. The format is `PairingCodec`'s; this file seals, opens and stores.
//

import Foundation
import OccultaFormats

extension ContactManager {

    enum PairingStoreError: Error, Equatable {
        case sealFailed
    }

    /// The state sealed on `key`, or `nil` if the column holds something that can't be read: it won't open under the local
    /// key (a launch left on legacy keys over a resealed store) or won't decode (a codec this build doesn't know, after a
    /// downgrade). A column never filled, which only a row the launch migration has yet to reach has, is an empty state.
    ///
    /// The two are different: an empty state is a plain pairing, which is sent to the old way and accepts the old form. A
    /// column that can't be read may be a pair-key pairing, and sending it the old way, or accepting an old-form file for it,
    /// is the fallback to the identity key that pair keys exist to end. So a send and a receive treat it as neither.
    func readablePairingState(of key: Contact.Profile.Key) -> PairingState? {
        guard let sealed = key.pairingEncrypted else { return .empty }
        guard let plaintext = sealed.decrypt(), let state = try? PairingCodec().decode(plaintext) else { return nil }
        return state
    }

    /// The state sealed on `key`; an unreadable column reads as empty, which suits a display and nothing that sends or
    /// receives (see `readablePairingState`).
    func pairingState(of key: Contact.Profile.Key) -> PairingState {
        self.readablePairingState(of: key) ?? .empty
    }

    /// Whether `contact`'s current pairing can be read. A contact with no current key has none to read.
    func pairingIsReadable(for contact: Contact.Profile) -> Bool {
        guard let key = contact.currentKey else { return true }
        return self.readablePairingState(of: key) != nil
    }

    /// Seals `state` into `key`. Doesn't save; the caller does.
    func store(_ state: PairingState, in key: Contact.Profile.Key) throws {
        guard let sealed = try PairingCodec().encode(state).encrypt() else {
            throw PairingStoreError.sealFailed
        }
        key.pairingEncrypted = sealed
    }

    /// The sealed form of `state`, for a row not yet inserted.
    func sealedPairing(_ state: PairingState) throws -> Data {
        guard let sealed = try PairingCodec().encode(state).encrypt() else {
            throw PairingStoreError.sealFailed
        }
        return sealed
    }

    /// The state on `contact`'s current key: the latest one not expired, the key every send and receive uses.
    func pairingState(for contact: Contact.Profile) -> PairingState {
        guard let key = contact.currentKey else { return .empty }
        return self.pairingState(of: key)
    }

    // MARK: - Sending and receiving

    /// The secret to seal a file to `contact` with, or nil: the pairing holds one, the peer is known to hold it too, and
    /// the peer is at the pairing tier. Anything less sends as before.
    func routingKeyForSending(to contact: Contact.Profile, tier: OccultaBundle.Version) -> Data? {
        let state = self.pairingState(for: contact)
        // A pair-key pairing is in the routing-key form whatever tier is stored: it never falls back to the identity key,
        // which holds nothing of it (Bug 196, stage 2).
        guard state.keys != nil || tier.isAtLeast(.pairingCapable) else { return nil }
        return state.sendsNewForm ? state.secret : nil
    }

    /// The pair keys to seal a slot to `contact` with, or nil for a pairing without them. Used only beside a routing key.
    func pairingSlotKeys(for contact: Contact.Profile) -> PairingSlotKeys? {
        self.pairingState(for: contact).keys.map { PairingSlotKeys(keys: $0, provider: self.pairKeys) }
    }

    /// What a pairing contributes to opening a file from `contact`: its secret, once held, and whether an old-form file
    /// may still be tried against it. nil when there is no secret to route by.
    func pairingSlotContext(for contact: Contact.Profile) -> Manager.Crypto.PairingSlotContext? {
        let state = self.pairingState(for: contact)
        return state.secret.map {
            Manager.Crypto.PairingSlotContext(
                secret: $0, acceptsOldForm: !state.refusesOldForm,
                pair: state.keys.map { PairingSlotKeys(keys: $0, provider: self.pairKeys) }
            )
        }
    }

    /// Whether `bundle` names `contact` as its sender by a pairing routing tag: some slot carries
    /// `RoutingKey.routingTag(secret, bundle.fingerprintNonce)` for the secret `contact` holds.
    func bundleCarriesRoutingTag(of contact: Contact.Profile, in bundle: OccultaBundle) -> Bool {
        guard let secret = self.pairingState(for: contact).secret, let recipients = bundle.group?.recipients else {
            return false
        }
        let tag = RoutingKey.routingTag(routingKey: secret, nonce: bundle.fingerprintNonce)
        return recipients.contains { $0.routingTag == tag }
    }

    /// Whether an old-form file (the sender named by identity fingerprint) may be attributed to `contact`. Not once the
    /// pairing began with a secret: such a file is another pairing's (Bug 196).
    func acceptsOldForm(from contact: Contact.Profile) -> Bool {
        // A pairing whose column can't be read may be a pair-key pairing: it refuses the old form (Bug 196).
        guard let key = contact.currentKey else { return true }
        return self.readablePairingState(of: key).map { !$0.refusesOldForm } ?? false
    }

    // MARK: - The first prekeys of a pairing

    /// Installs a pairing's first prekeys into `contact`'s record and records the peer at the pairing tier.
    /// Doesn't save; the caller does, in the same save as the key row.
    ///
    /// Our batch goes in pending as it was sent, so it keeps travelling until the peer uses a key from it, and the peer's
    /// is accepted through the bookkeeper's rules. A peer batch outside the record's limits, which no build of ours
    /// produces, is dropped and the pairing goes on with only our side. Everything else the record held of an earlier
    /// pairing is retired (`PrekeyBookkeeper.startPairing`).
    ///
    /// The peer sent a batch, so it runs 2.0.1 or later: the tier is recorded now, which lets the first message be
    /// sent in the group format, and in the pairing form once stage 5's gate allows.
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

        if let byte = OccultaBundle.Version.pairingCapable.wireByte {
            contact.maxBundleVersion = try Manager.Crypto().encrypt(data: Data([byte]))
        }
    }
}

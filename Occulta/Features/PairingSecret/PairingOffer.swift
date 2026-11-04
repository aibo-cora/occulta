//
//  PairingOffer.swift
//  Occulta
//
//  What a key exchange hands to `save()` for the pairing secret and the first prekeys (`bugs.md` Bug 196): our batch
//  as a scratch prekey record, the batch the peer sent, and the nonces both sides committed to. Present only when
//  both phones sent a batch, which is also the signal that both can hold a pairing secret: a 2.0.0 phone sends none.
//

import Foundation
import OccultaFormats

nonisolated
struct PairingOffer: Equatable {

    /// Our nonce and the peer's, from the discovery messages. A classical exchange has them too, with a peer that
    /// sends one.
    let ourNonce: Data
    let peerNonce: Data

    /// The record we'll hold for this peer: one pending batch of our keys, Enclave blobs kept in memory only until
    /// `save()` installs them. An exchange that is abandoned leaves nothing behind: CryptoKit Enclave keys have no
    /// keychain item.
    let ownPrekeys: PrekeyRecord

    /// The batch the peer sent in its identity message, as received.
    let peerBatch: Batch

    struct Batch: Equatable {
        let id: Data?
        let generatedAt: Date
        let prekeys: [OccultaBundle.WirePrekey]
        let lastResort: OccultaBundle.WirePrekey?

        init(_ wire: OccultaBundle.SealedPayload.PrekeySyncBatch) {
            self.id          = wire.id
            self.generatedAt = wire.generatedAt
            self.prekeys     = wire.prekeys
            self.lastResort  = wire.lastResort
        }
    }

    /// The secret this pairing holds, derived from the identity ECDH, both nonces and the ML-KEM secrets where the
    /// exchange had them. Both phones get the same bytes. `nil` if the key manager couldn't derive it, in which case the
    /// pairing is made as it was before this fix.
    func secret(withPeer peerIdentity: Data, quantum: QuantumKeyMaterial?, using keyManager: any KeyManagerProtocol) -> Data? {
        keyManager.createPairingSecret(
            peerP256Material: peerIdentity, quantumMaterial: quantum, ourNonce: self.ourNonce, peerNonce: self.peerNonce
        )
    }

    /// Our pending batch in wire form: what the identity message carries.
    static func wireBatch(of record: PrekeyRecord) -> OccultaBundle.SealedPayload.PrekeySyncBatch? {
        PrekeyBookkeeper().pendingBatch(in: record, publicKeyOfBlob: Manager.PrekeySecretsManager.publicKey(ofBlob:)).map {
            OccultaBundle.SealedPayload.PrekeySyncBatch(
                generatedAt: $0.generatedAt, prekeys: $0.prekeys, id: $0.id, lastResort: $0.lastResort
            )
        }
    }
}

extension PairingOffer {

    /// A scratch record holding one fresh pending batch: the batch size's one-time keys and a last-resort key, all
    /// made in the Enclave, the same as `ContactManager.installFreshBatch(into:)` makes for a contact.
    @MainActor
    static func makeOwnPrekeys(now: Date = Date()) throws -> PrekeyRecord {
        let batchSize = Manager.PrekeySecretsManager.defaultBatchSize
        let blobs = try Manager.PrekeySecretsManager().generateEnclaveKeys(count: batchSize + 1)
        var record = PrekeyRecord.empty
        PrekeyBookkeeper().install(Array(blobs.prefix(batchSize)), lastResort: blobs[batchSize], into: &record, now: now)
        return record
    }
}

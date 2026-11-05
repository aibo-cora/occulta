//
//  PairingSlotKeys.swift
//  Occulta
//
//  What a slot to or from a pair-key pairing uses in place of the identity key (`bugs.md` Bug 196, stage 2): the long-term
//  slot key comes from the pair-key ECDH, and a forward-secret slot is signed by the pair signing key and verified against
//  the one the peer sent. The private halves are Enclave blobs held in the pairing's sealed column; this type reads them
//  through the injected provider and keeps nothing.
//
//  The slot's routing key, tag and proof are unchanged (`RoutingKey`), and so is everything else that stays on the identity
//  key: the sender proof's key, backup pieces, signed attributes.
//

import Foundation
import CryptoKit
import OccultaFormats

struct PairingSlotKeys {

    enum SlotKeyError: Error {
        /// The Enclave couldn't use the pair key, or the ML-KEM secrets are not 32 bytes. The slot is not sealed or opened;
        /// nothing falls back to the identity key.
        case unavailable
    }

    private let keys: PairKeys
    private let provider: any CardKeyProviding

    init(keys: PairKeys, provider: any CardKeyProviding) {
        self.keys = keys
        self.provider = provider
    }

    /// The long-term slot key for this pairing, with the ML-KEM secrets where the slot is hybrid. The same on both phones.
    func longTermKey(quantumMaterial: QuantumKeyMaterial?) throws -> SymmetricKey {
        guard
            let raw = try? self.provider.sharedSecret(agreementBlob: self.keys.ourAgreementBlob, peerPublicKey: self.keys.peerAgreementKey),
            let key = RoutingKey.longTermKey(
                pairwiseECDH: Manager.Crypto.cardECDHOutput(raw), ourAgreementKey: self.keys.ourAgreementKey,
                peerAgreementKey: self.keys.peerAgreementKey,
                mlkemSecrets: quantumMaterial.map { ($0.encapsulatedSecret, $0.decapsulatedSecret) }
            )
        else { throw SlotKeyError.unavailable }
        return key
    }

    /// A DER signature over `payload` by the pair signing key.
    func sign(_ payload: Data) throws -> Data {
        guard let signature = try? self.provider.signDER(payload, signingBlob: self.keys.ourSigningBlob) else {
            throw SlotKeyError.unavailable
        }
        return signature
    }

    /// Whether `signature` is the peer's pair signing key's over the domain-separated ephemeral key. The prefixed form only:
    /// no build before 1.10.2 has a pair key, so the bare form can't be a legitimate one here.
    func verifies(_ signature: Data, ephemeralPublicKey: Data, using crypto: Manager.Crypto) -> Bool {
        crypto.verifySenderEphemeralSignature(
            signature, ephemeralPublicKey: ephemeralPublicKey, senderPublicKey: self.keys.peerSigningKey, acceptsBareForm: false
        )
    }
}

//
//  Crypto+Manager+KeyDerivation.swift
//  Occulta
//

import Foundation
import CryptoKit

// MARK: - Outbound key derivation (shared by both seal overloads)

extension Manager.Crypto {

    /// Derive a symmetric key and build the matching SecrecyContext for an outbound slot.
    ///
    /// `contactPrekey != nil` → FS path: ephemeral ECDH [+ ML-KEM]
    /// `contactPrekey == nil` → fallback: long-term ECDH [+ ML-KEM]
    ///
    /// Called by `seal(message:contactPrekey:...)` (single-recipient) and
    /// `wrapRecipient` inside `seal(message:groupID:recipients:)`.
    func deriveOutboundKey(
        contactPrekey: Prekey?,
        recipientPublicKey: Data,
        quantumMaterial: QuantumKeyMaterial?
    ) throws -> (key: SymmetricKey, context: OccultaBundle.SecrecyContext) {
        if let prekey = contactPrekey {
            guard prekey.publicKey.count == 65 else { throw EncryptionError.invalidPrekeyMaterial }
            guard let (ephemeralPriv, ephemeralPub) = self.keyManager.generateEphemeralKeyPair() else {
                throw EncryptionError.ephemeralKeyGenerationFailed
            }
            guard let key = self.deriveSessionKey(
                ephemeralPrivateKey: ephemeralPriv,
                recipientMaterial: prekey.publicKey,
                quantumMaterial: quantumMaterial
            ) else { throw EncryptionError.keyDerivationFailed }

            let mode: OccultaBundle.Mode = quantumMaterial != nil ? .forwardSecret : .forwardSecretNoPQ
            let context = OccultaBundle.SecrecyContext(
                mode: mode, ephemeralPublicKey: ephemeralPub, prekeyID: prekey.id
            )
            return (key, context)
        } else {
            guard let key = self.deriveSessionKey(using: recipientPublicKey, quantumMaterial: quantumMaterial) else {
                throw EncryptionError.keyDerivationFailed
            }
            let mode: OccultaBundle.Mode = quantumMaterial != nil ? .longTermFallback : .longTermNoPQ
            let context = OccultaBundle.SecrecyContext(
                mode: mode, ephemeralPublicKey: Data(), prekeyID: nil
            )
            return (key, context)
        }
    }
}

// MARK: - Inbound key derivation (shared by decryptSealed and openGroup)

extension Manager.Crypto {

    /// Derive the symmetric key for an inbound SecrecyContext.
    ///
    /// FS modes: look up the prekey private key, ECDH, return the Prekey for post-open consumption.
    /// Fallback modes: long-term ECDH, no prekey to consume (returns nil).
    ///
    /// `quantumMaterial` must already be resolved by the caller (nil for NoPQ modes).
    ///
    /// Called by `decryptSealed` (single-recipient) and `openGroup` (group path).
    func deriveInboundKey(
        secrecy: OccultaBundle.SecrecyContext,
        senderContactID: String,
        senderPublicKey: Data,
        quantumMaterial: QuantumKeyMaterial?,
        prekeyManager: Manager.PrekeyManager
    ) throws -> (key: SymmetricKey, consumablePrekey: Prekey?) {
        switch secrecy.mode {
        case .forwardSecret, .forwardSecretNoPQ:
            guard let prekeyID = secrecy.prekeyID else { throw EncryptionError.keyDerivationFailed }
            #if DEBUG
            debugPrint("Using prekey, ID = \(prekeyID)")
            #endif
            let temp = Prekey(id: prekeyID, contactID: senderContactID, publicKey: Data())
            guard
                let privKey = prekeyManager.retrievePrivateKey(for: temp),
                let key = self.deriveSessionKey(
                    ephemeralPrivateKey: privKey,
                    recipientMaterial: secrecy.ephemeralPublicKey,
                    quantumMaterial: quantumMaterial
                )
            else { throw EncryptionError.keyDerivationFailed }
            return (key, temp)

        case .longTermFallback, .longTermNoPQ:
            guard let key = self.deriveSessionKey(using: senderPublicKey, quantumMaterial: quantumMaterial) else {
                throw EncryptionError.keyDerivationFailed
            }
            return (key, nil)

        case .group, .unsupported:
            throw OccultaBundle.BundleError.unsupportedMode
        }
    }
}

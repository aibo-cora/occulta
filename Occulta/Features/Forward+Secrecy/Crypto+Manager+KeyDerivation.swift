//
//  Crypto+Manager+KeyDerivation.swift
//  Occulta
//

import Foundation
import CryptoKit
import OccultaFormats

// MARK: - Outbound key derivation (shared by both seal overloads)

extension Manager.Crypto {

    /// Derive a symmetric key and build the matching SecrecyContext for an outbound slot.
    ///
    /// `contactPrekey != nil` → FS path: ephemeral ECDH [+ ML-KEM]
    /// `contactPrekey == nil` → fallback: long-term ECDH [+ ML-KEM]
    ///
    /// For a last-resort key (`isLastResort`) the `prekeyID` written is
    /// `SecrecyContext.lastResortPrekeyID`, never the key's own ID, which would link every bundle sealed to it.
    ///
    /// Called by `seal(message:contactPrekey:...)` (single-recipient) and
    /// `wrapRecipient` inside `seal(message:groupID:recipients:)`.
    func deriveOutboundKey(
        contactPrekey: Prekey?,
        isLastResort: Bool = false,
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

            let prekeyID: String
            if isLastResort {
                guard let derived = OccultaBundle.SecrecyContext.lastResortPrekeyID(
                    keyID: prekey.id, ephemeralPublicKey: ephemeralPub
                ) else { throw EncryptionError.invalidPrekeyMaterial }
                prekeyID = derived
            } else {
                prekeyID = prekey.id
            }
            let mode: OccultaBundle.Mode = quantumMaterial != nil ? .forwardSecret : .forwardSecretNoPQ
            let context = OccultaBundle.SecrecyContext(
                mode: mode, ephemeralPublicKey: ephemeralPub, prekeyID: prekeyID
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

/// Which of our keys opened an inbound bundle or slot.
enum InboundPrekeyUse: Equatable {
    /// A one-time prekey, which is consumed as it opens (§2.2 of `SECURITY_CHECKLIST.md`).
    case oneTime(Prekey)
    /// A last-resort prekey, which stays (prekey continuity §3.1). Its own ID, not the bundle's derived one.
    case lastResort(keyID: String)
    /// The long-term identity keys.
    case longTerm

    /// The one-time prekey to consume, if that's what opened it.
    var consumable: Prekey? {
        if case .oneTime(let prekey) = self { return prekey }
        return nil
    }

    var isLastResort: Bool {
        if case .lastResort = self { return true }
        return false
    }
}

extension Manager.Crypto {

    /// Derive the symmetric key for an inbound SecrecyContext.
    ///
    /// FS modes: look up the one-time prekey the `prekeyID` names, or else the last-resort key it was derived from,
    /// ECDH, and report which (`InboundPrekeyUse`). Fallback modes: long-term ECDH.
    ///
    /// The private key comes from `prekeys`: an Enclave key rebuilt from the sender's record, or a legacy
    /// keychain key. Both derive through the same function (`Manager.Key.forwardSecretSessionKey`), so a
    /// sender can't tell which one it sealed to.
    ///
    /// NoPQ mode variants always use nil quantum material regardless of what the caller passes —
    /// the mode name is authoritative. This lets `openGroup` pass the same quantum material to
    /// all trial-decryption slots without mismatching NoPQ slots that the sender sealed without ML-KEM.
    ///
    /// Called by `decryptSealed` (single-recipient) and `openGroup` (group path).
    func deriveInboundKey(
        secrecy: OccultaBundle.SecrecyContext,
        senderContactID: String,
        senderPublicKey: Data,
        quantumMaterial: QuantumKeyMaterial?,
        prekeys: PrekeyPrivateKeys
    ) throws -> (key: SymmetricKey, used: InboundPrekeyUse) {
        switch secrecy.mode {
        case .forwardSecret, .forwardSecretNoPQ:
            guard let prekeyID = secrecy.prekeyID else { throw EncryptionError.keyDerivationFailed }
            #if DEBUG
            debugPrint("Using prekey, ID = \(prekeyID)")
            #endif
            let temp = Prekey(id: prekeyID, contactID: senderContactID, publicKey: Data())
            // NoPQ: sender did not use ML-KEM — ignore any quantum material on file.
            let effectiveQM: QuantumKeyMaterial? = secrecy.mode == .forwardSecretNoPQ ? nil : quantumMaterial
            let privateKey: PrekeyPrivateKey
            let used: InboundPrekeyUse
            if let oneTime = prekeys.privateKey(forPrekeyID: prekeyID, contactID: senderContactID) {
                (privateKey, used) = (oneTime, .oneTime(temp))
            } else if let (keyID, lastResort) = prekeys.lastResortKey(
                forPrekeyID: prekeyID, ephemeralPublicKey: secrecy.ephemeralPublicKey
            ) {
                (privateKey, used) = (lastResort, .lastResort(keyID: keyID))
            } else {
                throw EncryptionError.keyDerivationFailed
            }
            let key: SymmetricKey?
            switch privateKey {
            case .keychain(let secKey):
                key = self.deriveSessionKey(
                    ephemeralPrivateKey: secKey, recipientMaterial: secrecy.ephemeralPublicKey, quantumMaterial: effectiveQM
                )
            case .enclave(let enclaveKey):
                key = (try? P256.KeyAgreement.PublicKey(x963Representation: secrecy.ephemeralPublicKey))
                    .flatMap { try? enclaveKey.sharedSecretFromKeyAgreement(with: $0) }
                    .flatMap { self.deriveSessionKey(
                        sharedSecret: $0, ownPublicKey: enclaveKey.publicKey.x963Representation,
                        recipientMaterial: secrecy.ephemeralPublicKey, quantumMaterial: effectiveQM
                    ) }
            }
            guard let key else { throw EncryptionError.keyDerivationFailed }
            return (key, used)

        case .longTermFallback, .longTermNoPQ:
            // NoPQ: sender did not use ML-KEM — ignore any quantum material on file.
            let effectiveQM: QuantumKeyMaterial? = secrecy.mode == .longTermNoPQ ? nil : quantumMaterial
            guard let key = self.deriveSessionKey(using: senderPublicKey, quantumMaterial: effectiveQM) else {
                throw EncryptionError.keyDerivationFailed
            }
            return (key, .longTerm)

        case .group, .unsupported:
            throw OccultaBundle.BundleError.unsupportedMode
        }
    }
}

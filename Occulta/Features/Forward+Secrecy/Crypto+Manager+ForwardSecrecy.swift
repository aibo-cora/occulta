//
//  Crypto+ForwardSecrecy.swift
//  Occulta
//
//  Created by Yura on 3/14/26.
//

import Foundation
import CryptoKit

// MARK: - Forward-secret encryption

extension Manager.Crypto {
    /// Encrypt a message for a single recipient.
    ///
    /// ## Invariant: no silent security degradation
    /// If `contactPrekey` is non-nil, the caller explicitly requested the FS path.
    /// Any failure in that path (ephemeral key generation, ECDH with the prekey)
    /// throws `EncryptionError` rather than silently falling back to the long-term
    /// key path. Silent fallback would mean the caller believes they sent FS when
    /// they actually sent with the long-term key.
    ///
    /// The fallback path is entered ONLY when `contactPrekey` is nil — meaning the
    /// caller explicitly chose the fallback (exhausted prekeys).
    ///
    /// ## SE ordering
    /// `keyManager.retrieveIdentity()` is the only SE read here. All SE writes
    /// (generateBatch) are done by the caller (ContactManager) before this call.
    func seal(message: Data, contactPrekey: Prekey?, recipientMaterial: Data, quantumMaterial: QuantumKeyMaterial? = nil, version: OccultaBundle.Version = OccultaBundle.currentVersion) throws -> OccultaBundle {
        guard
            recipientMaterial.count == 65
        else {
            throw EncryptionError.invalidRecipientMaterial
        }

        let ourPublicKey = try self.keyManager.retrieveIdentity()

        let fingerprintNonce  = try OccultaBundle.SecrecyContext.generateNonce()
        let senderFingerprint = OccultaBundle.SecrecyContext.fingerprint(for: ourPublicKey, nonce: fingerprintNonce)
        
        let (sessionKey, secrecy) = try self.deriveOutboundKey(
            contactPrekey: contactPrekey,
            recipientPublicKey: recipientMaterial,
            quantumMaterial: quantumMaterial
        )

        let aad = try OccultaBundle.computeAdditionalAuthentication(version: version, secrecy: secrecy)
        guard let ciphertext = try AES.GCM.seal(message, using: sessionKey, nonce: AES.GCM.Nonce(), authenticating: aad).combined else {
            throw EncryptionError.sealFailed
        }

        debugPrint("Sealing message, using mode: \(secrecy.mode)")

        return OccultaBundle(version: version, secrecy: secrecy, ciphertext: ciphertext, fingerprintNonce: fingerprintNonce, senderFingerprint: senderFingerprint)
    }
}

// MARK: - Session key derivation

extension Manager.Crypto {
    /// Derive a session key from an ephemeral or prekey private key.
    /// Called by ContactManager. SecKey must be released by caller before consume().
    /// Derive a session key from an ephemeral or prekey private key.
    func deriveSessionKey(ephemeralPrivateKey: SecKey, recipientMaterial: Data, quantumMaterial: QuantumKeyMaterial? = nil) -> SymmetricKey? {
        if let quantumMaterial {
            return self.keyManager.createHybridFSSharedSecret(ephemeralPrivateKey: ephemeralPrivateKey, recipientMaterial: recipientMaterial, quantumMaterial: quantumMaterial)
        } else {
            return self.keyManager.createSharedSecret(ephemeralPrivateKey: ephemeralPrivateKey, recipientMaterial: recipientMaterial)
        }
    }

    /// Derive a session key using the long-term identity key.
    func deriveSessionKey(using material: Data, quantumMaterial: QuantumKeyMaterial? = nil) -> SymmetricKey? {
        if let quantumMaterial {
            return self.keyManager.createHybridSharedSecret(peerP256Material: material, quantumMaterial: quantumMaterial)
        } else {
            return self.keyManager.createSharedSecret(using: material)
        }
    }
}

// MARK: - Bundle open

extension Manager.Crypto {
    /// Open a sealed bundle with a pre-derived session key.
    ///
    /// SecKey must be released and consume() must not yet be called when this is invoked.
    func open(_ bundle: OccultaBundle, using sessionKey: SymmetricKey) throws -> Data {
        let aad = try OccultaBundle.computeAdditionalAuthentication(version: bundle.version, secrecy: bundle.secrecy)
        let box = try AES.GCM.SealedBox(combined: bundle.ciphertext)
        
        return try AES.GCM.open(box, using: sessionKey, authenticating: aad)
    }
}

// MARK: - Errors

extension Manager.Crypto {
    enum EncryptionError: Error {
        case sealFailed
        case keyDerivationFailed
        case ephemeralKeyGenerationFailed
        /// `recipientMaterial` (long-term key) is not a valid 65-byte P-256 x963 key.
        case invalidRecipientMaterial
        /// `contactPrekey.publicKey` from an inbound batch is not a valid 65-byte key.
        case invalidPrekeyMaterial
        /// `sealGroup` was called with an empty recipients array.
        case noRecipients
    }
}

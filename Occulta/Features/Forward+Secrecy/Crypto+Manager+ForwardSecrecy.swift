//
//  Crypto+ForwardSecrecy.swift
//  Occulta
//
//  Created by Yura on 3/14/26.
//

import Foundation
import CryptoKit

// MARK: - Forward-secret encryption / decryption

extension Manager.Crypto {

    // MARK: - Encryption

    /// Encrypt a message for a single recipient.
    ///
    /// ## Responsibilities of this function
    /// - Crypto operations only: ECDH, HKDF, AES-GCM, fingerprint.
    /// - No SE side effects. No replenishment. No SwiftData.
    ///
    /// ## Caller (ContactManager) is responsible for
    /// - Deciding whether to replenish prekeys BEFORE calling this method.
    /// - Passing the pre-computed `outboundBatch` (or nil).
    /// - Updating `outboundPrekeySequence` on the contact model after.
    /// - Persisting all model changes.
    ///
    /// ## Forward secret path (`contactPrekey` non-nil)
    /// ```
    /// sessionKey = HKDF(ECDH(ephemeralPriv, contactPrekey.publicKey))
    /// ```
    ///
    /// ## Fallback path (`contactPrekey` nil)
    /// ```
    /// sessionKey = HKDF(ECDH(ourLongTermSEKey, recipientMaterial))
    /// ```
    ///
    /// - Parameters:
    ///   - message:           Plaintext payload.
    ///   - contactPrekey:     Oldest prekey from contact's store, or nil for fallback.
    ///   - recipientMaterial: Recipient's long-term public key in x963 format.
    ///   - outboundBatch:     Pre-computed replenishment batch, or nil if not needed.
    ///                        Caller generates this via PrekeyManager BEFORE calling here.
    /// - Returns:
    ///   - `bundle`: The sealed ``OccultaBundle``.
    /// - Throws: `EncryptionError` or `CryptoKit` errors.
    func encryptForwardSecret(
        message: Data,
        contactPrekey: Prekey?,
        recipientMaterial: Data,
        outboundBatch: OccultaBundle.PrekeySyncBatch?
    ) throws -> OccultaBundle {

        let ourPublicKey = try self.keyManager.retrieveIdentity()

        let fingerprintNonce  = OccultaBundle.SecrecyContext.generateNonce()
        let senderFingerprint = OccultaBundle.SecrecyContext.fingerprint(
            for: ourPublicKey,
            nonce: fingerprintNonce
        )

        // ── Forward secret path ──────────────────────────────────────────
        if let contactPrekey {
            guard
                let (ephemeralPrivateKey, ephemeralPublicKeyData) =
                    self.keyManager.generateEphemeralKeyPair()
            else {
                return try self.fallback(
                    message:           message,
                    recipientMaterial: recipientMaterial,
                    ourPublicKey:      ourPublicKey,
                    fingerprintNonce:  fingerprintNonce,
                    senderFingerprint: senderFingerprint,
                    outboundBatch:     outboundBatch
                )
            }

            guard
                let sessionKey = self.keyManager.createSharedSecret(ephemeralPrivateKey: ephemeralPrivateKey, recipientMaterial:   contactPrekey.publicKey)
            else {
                return try self.fallback(
                    message:           message,
                    recipientMaterial: recipientMaterial,
                    ourPublicKey:      ourPublicKey,
                    fingerprintNonce:  fingerprintNonce,
                    senderFingerprint: senderFingerprint,
                    outboundBatch:     outboundBatch
                )
            }

            // ephemeralPrivateKey released here — forward secrecy established.

            let secrecy = OccultaBundle.SecrecyContext(
                mode:               .forwardSecret,
                ephemeralPublicKey: ephemeralPublicKeyData,
                prekeyID:           contactPrekey.id,
                prekeySequence:     contactPrekey.sequence,
                prekeyBatch:        outboundBatch
            )

            let aad = try Self.encodeAAD(secrecy)

            guard
                let ciphertext = try AES.GCM.seal(message, using: sessionKey, nonce: AES.GCM.Nonce(), authenticating: aad).combined
            else {
                throw EncryptionError.sealFailed
            }

            return OccultaBundle(
                version:           OccultaBundle.currentVersion,
                secrecy:           secrecy,
                ciphertext:        ciphertext,
                fingerprintNonce:  fingerprintNonce,
                senderFingerprint: senderFingerprint
            )
        }

        // ── Long-term fallback path ──────────────────────────────────────
        return try self.fallback(
            message:           message,
            recipientMaterial: recipientMaterial,
            ourPublicKey:      ourPublicKey,
            fingerprintNonce:  fingerprintNonce,
            senderFingerprint: senderFingerprint,
            outboundBatch:     outboundBatch
        )
    }

    // MARK: - Decryption

    /// Derive a session key using an ephemeral private key and recipient material.
    ///
    /// Used by ContactManager to compute the session key for the FS path
    /// BEFORE calling openBundle. The SecKey must be released by the caller
    /// before any SecItemDelete is called.
    func deriveSessionKey(ephemeralPrivateKey: SecKey, recipientMaterial: Data) -> SymmetricKey? {
        self.keyManager.createSharedSecret(ephemeralPrivateKey: ephemeralPrivateKey, recipientMaterial: recipientMaterial)
    }

    /// Derive a session key using the long-term identity key and peer material.
    ///
    /// Used by ContactManager for the fallback path.
    func deriveSessionKey(using material: Data) -> SymmetricKey? {
        self.keyManager.createSharedSecret(using: material)
    }

    /// Open a sealed AES-GCM bundle with a pre-derived session key.
    ///
    /// ## This function is purely AES-GCM. Zero SE access.
    ///
    /// All key derivation (SE operations) must be complete and all SecKey
    /// references must be released before calling this function.
    /// ContactManager is responsible for:
    /// - Deriving the session key via deriveSessionKey(...)
    /// - Releasing the SecKey (goes out of scope before this call)
    /// - Calling PrekeyManager.consume() AFTER this call returns
    ///
    /// - Parameters:
    ///   - bundle:     The received ``OccultaBundle``.
    ///   - sessionKey: Pre-derived symmetric key. Caller owns derivation.
    /// - Returns: Decrypted plaintext.
    /// - Throws: CryptoKit if GCM tag verification fails.
    func open(_ bundle: OccultaBundle, using sessionKey: SymmetricKey) throws -> Data {
        let aad = try Self.encodeAAD(bundle.secrecy)
        let box = try AES.GCM.SealedBox(combined: bundle.ciphertext)
        
        return try AES.GCM.open(box, using: sessionKey, authenticating: aad)
    }

    // MARK: - Private helpers

    private func fallback(message: Data, recipientMaterial: Data, ourPublicKey: Data, fingerprintNonce: Data, senderFingerprint: Data, outboundBatch: OccultaBundle.PrekeySyncBatch?) throws -> OccultaBundle {
        guard
            let sessionKey = self.keyManager.createSharedSecret(using: recipientMaterial)
        else {
            throw EncryptionError.keyDerivationFailed
        }

        let secrecy = OccultaBundle.SecrecyContext(
            mode:               .longTermFallback,
            ephemeralPublicKey: ourPublicKey,
            prekeyID:           nil,
            prekeySequence:     nil,
            prekeyBatch:        outboundBatch
        )

        let aad = try Self.encodeAAD(secrecy)

        guard
            let ciphertext = try AES.GCM.seal(message, using: sessionKey, nonce: AES.GCM.Nonce(), authenticating: aad).combined
        else {
            throw EncryptionError.keyDerivationFailed
        }

        return OccultaBundle(
            version:           OccultaBundle.currentVersion,
            secrecy:           secrecy,
            ciphertext:        ciphertext,
            fingerprintNonce:  fingerprintNonce,
            senderFingerprint: senderFingerprint
        )
    }

}

// MARK: - AAD helper

extension Manager.Crypto {
    /// Encode a `SecrecyContext` as AAD with sorted keys.
    ///
    /// `.sortedKeys` guarantees identical byte output on both seal and open,
    /// regardless of Swift runtime version or `JSONEncoder` instance state.
    private static func encodeAAD(_ secrecy: OccultaBundle.SecrecyContext) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        
        return try encoder.encode(secrecy)
    }
}

// MARK: - Errors

extension Manager.Crypto {
    enum EncryptionError: Error {
        case sealFailed
        case keyDerivationFailed
    }
}

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
    func encryptForwardSecret(
        message:           Data,
        contactPrekey:     Prekey?,
        recipientMaterial: Data,
        outboundBatch:     OccultaBundle.PrekeySyncBatch?
    ) throws -> OccultaBundle {

        // Validate long-term public key length (Finding 6)
        guard recipientMaterial.count == 65 else {
            throw EncryptionError.invalidRecipientMaterial
        }

        let ourPublicKey = try self.keyManager.retrieveIdentity()

        // Finding 3: throws on entropy failure — never produce a static nonce
        let fingerprintNonce  = try OccultaBundle.SecrecyContext.generateNonce()
        let senderFingerprint = OccultaBundle.SecrecyContext.fingerprint(
            for: ourPublicKey, nonce: fingerprintNonce
        )

        // ── Forward secret path (contactPrekey non-nil) ──────────────────
        if let contactPrekey {

            // Validate the prekey's public key before ECDH.
            // contactPrekey.publicKey comes from a received PrekeySyncBatch —
            // attacker-influenced data. Reject invalid material explicitly
            // rather than letting it fail silently two layers down.
            guard contactPrekey.publicKey.count == 65 else {
                throw EncryptionError.invalidPrekeyMaterial
            }

            // Ephemeral key generation failure with a valid prekey is unexpected —
            // throw instead of silently degrading to the long-term path.
            guard
                let (ephemeralPrivateKey, ephemeralPublicKeyData) =
                    self.keyManager.generateEphemeralKeyPair()
            else {
                throw EncryptionError.ephemeralKeyGenerationFailed
            }

            // ECDH failure with a valid 65-byte prekey public key is unexpected —
            // throw instead of silently degrading to the long-term path.
            guard
                let sessionKey = self.keyManager.createSharedSecret(
                    ephemeralPrivateKey: ephemeralPrivateKey,
                    recipientMaterial:   contactPrekey.publicKey
                )
            else {
                throw EncryptionError.keyDerivationFailed
            }

            // ephemeralPrivateKey goes out of scope here — never persisted.

            let secrecy = OccultaBundle.SecrecyContext(
                mode:               .forwardSecret,
                ephemeralPublicKey: ephemeralPublicKeyData,
                prekeyID:           contactPrekey.id,
                prekeySequence:     contactPrekey.sequence,
                prekeyBatch:        outboundBatch
            )

            let aad = try Self.computeAAD(version: OccultaBundle.currentVersion, secrecy: secrecy)

            guard
                let ciphertext = try AES.GCM.seal(
                    message, using: sessionKey, nonce: AES.GCM.Nonce(),
                    authenticating: aad
                ).combined
            else { throw EncryptionError.sealFailed }

            return OccultaBundle(
                version:           OccultaBundle.currentVersion,
                secrecy:           secrecy,
                ciphertext:        ciphertext,
                fingerprintNonce:  fingerprintNonce,
                senderFingerprint: senderFingerprint
            )
        }

        // ── Long-term fallback path (contactPrekey nil) ──────────────────
        // Caller explicitly chose this path because prekeys are exhausted.
        return try self.fallback(
            message: message, recipientMaterial: recipientMaterial,
            ourPublicKey: ourPublicKey,
            fingerprintNonce: fingerprintNonce, senderFingerprint: senderFingerprint,
            outboundBatch: outboundBatch
        )
    }
}

// MARK: - Session key derivation

extension Manager.Crypto {

    /// Derive a session key from an ephemeral or prekey private key.
    /// Called by ContactManager. SecKey must be released by caller before consume().
    func deriveSessionKey(
        ephemeralPrivateKey: SecKey,
        recipientMaterial: Data
    ) -> SymmetricKey? {
        self.keyManager.createSharedSecret(
            ephemeralPrivateKey: ephemeralPrivateKey,
            recipientMaterial:   recipientMaterial
        )
    }

    /// Derive a session key using the long-term identity key.
    func deriveSessionKey(using material: Data) -> SymmetricKey? {
        self.keyManager.createSharedSecret(using: material)
    }
}

// MARK: - Bundle open

extension Manager.Crypto {

    /// Open a sealed bundle with a pre-derived session key. Pure AES-GCM, zero SE.
    ///
    /// `fullAAD()` includes `version` + `SecrecyContext` — any tampered field throws.
    /// SecKey must be released and consume() must not yet be called when this is invoked.
    func openBundle(_ bundle: OccultaBundle, using sessionKey: SymmetricKey) throws -> Data {
        let aad = try bundle.fullAAD()
        let box = try AES.GCM.SealedBox(combined: bundle.ciphertext)
        return try AES.GCM.open(box, using: sessionKey, authenticating: aad)
    }
}

// MARK: - Private helpers

extension Manager.Crypto {

    private func fallback(
        message:           Data,
        recipientMaterial: Data,
        ourPublicKey:      Data,
        fingerprintNonce:  Data,
        senderFingerprint: Data,
        outboundBatch:     OccultaBundle.PrekeySyncBatch?
    ) throws -> OccultaBundle {
        guard let sessionKey = self.keyManager.createSharedSecret(using: recipientMaterial) else {
            throw EncryptionError.keyDerivationFailed
        }

        let secrecy = OccultaBundle.SecrecyContext(
            mode:               .longTermFallback,
            ephemeralPublicKey: ourPublicKey,
            prekeyID:           nil,
            prekeySequence:     nil,
            prekeyBatch:        outboundBatch
        )

        let aad = try Self.computeAAD(version: OccultaBundle.currentVersion, secrecy: secrecy)

        guard
            let ciphertext = try AES.GCM.seal(
                message, using: sessionKey, nonce: AES.GCM.Nonce(),
                authenticating: aad
            ).combined
        else { throw EncryptionError.keyDerivationFailed }

        return OccultaBundle(
            version:           OccultaBundle.currentVersion,
            secrecy:           secrecy,
            ciphertext:        ciphertext,
            fingerprintNonce:  fingerprintNonce,
            senderFingerprint: senderFingerprint
        )
    }

    /// Compute AAD: `version.rawValue || sortedKeys(SecrecyContext)`.
    /// `.sortedKeys` is mandatory — without it encoder instances can produce
    /// different key orderings, causing spurious authenticationFailure.
    static func computeAAD(
        version: OccultaBundle.Version,
        secrecy: OccultaBundle.SecrecyContext
    ) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        var aad = version.rawValue.data(using: .utf8)!
        aad.append(contentsOf: try encoder.encode(secrecy))
        return aad
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
    }
}

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

    /// Encrypt a message or file for a single recipient with forward secrecy where possible.
    ///
    /// ## What the caller (ContactManager) does before this call:
    /// - Fetch and decrypt `contactPrekey` from the contact's stored prekeys.
    ///   Pass `nil` if the store is empty (triggers fallback path).
    /// - Provide `contactID` and `outboundPrekeySequence` from the contact model.
    ///
    /// ## What the caller does after this call:
    /// - Remove the consumed prekey from the contact's local store.
    /// - If `outboundBatch` is non-nil, encrypt each `Prekey` and replace the
    ///   contact's prekey store via `syncPrekeyData(_:sequence:)`.
    /// - Write `nextOutboundSequence` back to `Contact.Profile.outboundPrekeySequence`.
    /// - Save the model context.
    ///
    /// ## Forward secret path (`contactPrekey` is non-nil)
    /// ```
    /// sessionKey = HKDF(ECDH(ephemeralPriv, contactPrekey.publicKey))
    /// ```
    ///
    /// ## Fallback path (`contactPrekey` is nil)
    /// ```
    /// sessionKey = HKDF(ECDH(ourLongTermSEKey, recipientMaterial))
    /// ```
    /// Always generates a fresh batch so the next message can use FS.
    ///
    /// - Parameters:
    ///   - message:                Plaintext payload.
    ///   - contactPrekey:          Oldest ``Prekey`` for this contact, or `nil` for fallback.
    ///   - recipientMaterial:      Recipient's long-term public key in x963 format.
    ///   - contactID:              `Contact.Profile.identifier` of the recipient.
    ///   - outboundPrekeySequence: `Contact.Profile.outboundPrekeySequence` for this contact.
    /// - Returns:
    ///   - `bundle`:               Sealed ``OccultaBundle`` ready for transmission.
    ///   - `outboundBatch`:        Fresh ``PrekeySyncBatch`` or `nil` if no replenishment needed.
    ///   - `nextOutboundSequence`: New sequence value. Caller writes to contact model.
    /// - Throws: `EncryptionError` or `CryptoKit` errors.
    func encryptForwardSecret(
        message: Data,
        contactPrekey: Prekey?,
        recipientMaterial: Data,
        contactID: String,
        outboundPrekeySequence: Int
    ) throws -> (
        bundle: OccultaBundle,
        outboundBatch: OccultaBundle.PrekeySyncBatch?,
        nextOutboundSequence: Int
    ) {
        let prekeyManager = Manager.PrekeyManager()

        let ourPublicKey = try self.keyManager.retrieveIdentity()

        let fingerprintNonce  = OccultaBundle.SecrecyContext.generateNonce()
        let senderFingerprint = OccultaBundle.SecrecyContext.fingerprint(
            for: ourPublicKey,
            nonce: fingerprintNonce
        )

        // Proactively replenish if stock is low for this contact.
        var nextSequence = outboundPrekeySequence
        var outboundBatch: OccultaBundle.PrekeySyncBatch? = nil

        if prekeyManager.needsReplenishment(for: contactID) {
            let result = try prekeyManager.generateBatch(
                contactID: contactID,
                currentSequence: nextSequence
            )
            outboundBatch = OccultaBundle.PrekeySyncBatch(
                sequence: nextSequence,
                prekeys:  result.prekeys
            )
            nextSequence = result.nextSequence
        }

        // ── Forward secret path ──────────────────────────────────────────
        if let contactPrekey {
            guard
                let (ephemeralPrivateKey, ephemeralPublicKeyData) =
                    self.keyManager.generateEphemeralKeyPair()
            else {
                return try self.fallback(
                    message: message,
                    recipientMaterial: recipientMaterial,
                    ourPublicKey: ourPublicKey,
                    fingerprintNonce: fingerprintNonce,
                    senderFingerprint: senderFingerprint,
                    contactID: contactID,
                    currentSequence: nextSequence,
                    outboundBatch: outboundBatch
                )
            }

            guard
                let sessionKey = self.keyManager.createSharedSecret(
                    ephemeralPrivateKey: ephemeralPrivateKey,
                    recipientMaterial: contactPrekey.publicKey
                )
            else {
                return try self.fallback(
                    message: message,
                    recipientMaterial: recipientMaterial,
                    ourPublicKey: ourPublicKey,
                    fingerprintNonce: fingerprintNonce,
                    senderFingerprint: senderFingerprint,
                    contactID: contactID,
                    currentSequence: nextSequence,
                    outboundBatch: outboundBatch
                )
            }

            guard
                let ciphertext = try AES.GCM.seal(
                    message,
                    using: sessionKey,
                    nonce: AES.GCM.Nonce()
                ).combined
            else {
                throw EncryptionError.sealFailed
            }

            // ephemeralPrivateKey goes out of scope here — forward secrecy established.

            let secrecy = OccultaBundle.SecrecyContext(
                mode:               .forwardSecret,
                ephemeralPublicKey: ephemeralPublicKeyData,
                prekeyID:           contactPrekey.id,
                prekeySequence:     contactPrekey.sequence,
                fingerprintNonce:   fingerprintNonce,
                senderFingerprint:  senderFingerprint,
                prekeyBatch:        outboundBatch
            )

            return (
                OccultaBundle(version: OccultaBundle.currentVersion, secrecy: secrecy, ciphertext: ciphertext),
                outboundBatch,
                nextSequence
            )
        }

        // ── Long-term fallback path ──────────────────────────────────────
        // Generate a full fresh batch unconditionally — breaks the exhaustion cycle.
        let result       = try prekeyManager.generateBatch(
            contactID: contactID,
            currentSequence: nextSequence
        )
        let freshBatch   = OccultaBundle.PrekeySyncBatch(
            sequence: nextSequence,
            prekeys:  result.prekeys
        )
        nextSequence = result.nextSequence

        return try self.fallback(
            message: message,
            recipientMaterial: recipientMaterial,
            ourPublicKey: ourPublicKey,
            fingerprintNonce: fingerprintNonce,
            senderFingerprint: senderFingerprint,
            contactID: contactID,
            currentSequence: nextSequence,
            outboundBatch: freshBatch
        )
    }

    // MARK: - Decryption

    /// Decrypt a bundle using a specific prekey resolved by the caller.
    ///
    /// ## What the caller (ContactManager) does before this call:
    /// - Identify the sender via `isLikelySender(of:contactPublicKey:)`.
    /// - Fetch the matching stored `Prekey` from the sender's contact profile
    ///   using the raw prekey data (decrypt blob → decode Prekey → match by id).
    ///
    /// ## What the caller does after this call:
    /// - Remove the consumed prekey from the sender's local store.
    /// - If `inboundBatch` is non-nil: encrypt each prekey, call
    ///   `syncPrekeyData(_:sequence:)` on the sender's profile.
    /// - Persist plaintext to local SwiftData store immediately — the bundle
    ///   is now disposable; forward secrecy means it cannot be re-decrypted.
    /// - Save the model context.
    ///
    /// - Parameters:
    ///   - bundle: The ``OccultaBundle`` to decrypt.
    ///   - prekey: The stored ``Prekey`` matching `bundle.secrecy.prekeyID`.
    ///             Must carry the correct `contactID` for SE tag construction.
    ///             Pass `nil` to attempt long-term fallback only.
    /// - Returns:
    ///   - `plaintext`:    Decrypted payload, or `nil` if decryption fails.
    ///   - `inboundBatch`: Sender's fresh prekeys. Caller stores on sender's profile.
    /// - Throws: `CryptoKit` if GCM tag verification fails (tampering / corruption).
    func decryptForwardSecret(
        bundle: OccultaBundle,
        prekey: Prekey?
    ) throws -> (plaintext: Data?, inboundBatch: OccultaBundle.PrekeySyncBatch?) {

        let prekeyManager = Manager.PrekeyManager()
        let plaintext: Data?

        switch bundle.secrecy.mode {
        case .forwardSecret:
            guard let prekey else {
                // No prekey provided — attempt long-term fallback.
                plaintext = try? self.decryptLongTerm(bundle: bundle)
                return (plaintext, bundle.secrecy.prekeyBatch)
            }

            guard let prekeyPrivateKey = prekeyManager.retrievePrivateKey(for: prekey) else {
                // Prekey already consumed or pruned — attempt long-term fallback.
                plaintext = try? self.decryptLongTerm(bundle: bundle)
                return (plaintext, bundle.secrecy.prekeyBatch)
            }

            guard
                let sessionKey = self.keyManager.createSharedSecret(
                    ephemeralPrivateKey: prekeyPrivateKey,
                    recipientMaterial: bundle.secrecy.ephemeralPublicKey
                )
            else {
                return (nil, nil)
            }

            let box       = try AES.GCM.SealedBox(combined: bundle.ciphertext)
            let decrypted = try AES.GCM.open(box, using: sessionKey)

            // Delete prekey private key from SE immediately after successful open.
            // This is the moment forward secrecy is established for this message.
            // The session key can never be reconstructed — the private half is gone.
            prekeyManager.consume(prekey: prekey)

            plaintext = decrypted
        case .longTermFallback:
            plaintext = try self.decryptLongTerm(bundle: bundle)
        }

        return (plaintext, bundle.secrecy.prekeyBatch)
    }

    // MARK: - Private helpers

    private func fallback(
        message: Data,
        recipientMaterial: Data,
        ourPublicKey: Data,
        fingerprintNonce: Data,
        senderFingerprint: Data,
        contactID: String,
        currentSequence: Int,
        outboundBatch: OccultaBundle.PrekeySyncBatch?
    ) throws -> (
        bundle: OccultaBundle,
        outboundBatch: OccultaBundle.PrekeySyncBatch?,
        nextOutboundSequence: Int
    ) {
        guard
            let sessionKey = self.keyManager.createSharedSecret(using: recipientMaterial),
            let ciphertext = try AES.GCM.seal(
                message,
                using: sessionKey,
                nonce: AES.GCM.Nonce()
            ).combined
        else {
            throw EncryptionError.keyDerivationFailed
        }

        let secrecy = OccultaBundle.SecrecyContext(
            mode:               .longTermFallback,
            ephemeralPublicKey: ourPublicKey,
            prekeyID:           nil,
            prekeySequence:     nil,
            fingerprintNonce:   fingerprintNonce,
            senderFingerprint:  senderFingerprint,
            prekeyBatch:        outboundBatch
        )

        return (
            OccultaBundle(version: OccultaBundle.currentVersion, secrecy: secrecy, ciphertext: ciphertext),
            outboundBatch,
            currentSequence
        )
    }

    private func decryptLongTerm(bundle: OccultaBundle) throws -> Data? {
        guard
            let sessionKey = self.keyManager.createSharedSecret(
                using: bundle.secrecy.ephemeralPublicKey
            )
        else { return nil }

        let box = try AES.GCM.SealedBox(combined: bundle.ciphertext)
        return try AES.GCM.open(box, using: sessionKey)
    }
}

// MARK: - Errors

extension Manager.Crypto {
    enum EncryptionError: Error {
        case sealFailed
        case keyDerivationFailed
    }
}

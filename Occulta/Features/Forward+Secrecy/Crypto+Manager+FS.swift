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

    /// Encrypt a message or file for a single recipient.
    ///
    /// The caller (ContactManager) is responsible for all SwiftData operations:
    /// - Fetching `contactPrekey` from the contact's profile before calling.
    /// - Removing that prekey from the contact's local store after this call.
    /// - Persisting `outboundBatch` onto the contact's profile via `syncPrekeyBatch()`.
    ///
    /// This method performs only cryptographic operations on raw `Data`.
    ///
    /// ## Forward secret path (`contactPrekey` is non-nil)
    /// ```
    /// 1. Generate throwaway ephemeral key pair (in memory, not SE)
    /// 2. sessionKey = HKDF(ECDH(ephemeralPriv, contactPrekey.publicKey))
    /// 3. AES-GCM.seal(message, using: sessionKey)
    /// 4. Embed contactPrekey.id + contactPrekey.sequence in SecrecyContext
    ///    so recipient can reconstruct SE tag "prekey.<seq>.<id>"
    /// 5. Generate outboundBatch if stock is low
    /// 6. Return (bundle { mode: .forwardSecret }, outboundBatch)
    /// ```
    ///
    /// ## Fallback path (`contactPrekey` is nil)
    /// ```
    /// 1. sessionKey = HKDF(ECDH(ourLongTermSEKey, recipientMaterial))
    /// 2. AES-GCM.seal(message, using: sessionKey)
    /// 3. Generate fresh outboundBatch unconditionally — breaks exhaustion cycle
    /// 4. Return (bundle { mode: .longTermFallback }, outboundBatch)
    /// ```
    ///
    /// - Parameters:
    ///   - message:           Plaintext payload.
    ///   - contactPrekey:     Oldest ``Prekey`` fetched from contact's profile by caller.
    ///                        Pass `nil` to trigger the fallback path.
    ///   - recipientMaterial: Recipient's long-term public key in x963 format.
    /// - Returns:
    ///   - `bundle`: Sealed ``OccultaBundle`` ready for transmission.
    ///   - `outboundBatch`: Fresh ``PrekeySyncBatch`` for caller to sync on contact's
    ///     profile. `nil` if stock is healthy and no replenishment was needed.
    /// - Throws: `EncryptionError` or `CryptoKit` errors.
    func encryptForwardSecret(
        message: Data,
        contactPrekey: Prekey?,
        recipientMaterial: Data
    ) throws -> (bundle: OccultaBundle, outboundBatch: OccultaBundle.PrekeySyncBatch?) {

        let prekeyManager = Manager.PrekeyManager()

        // Retrieve our long-term public key for the sender fingerprint.
        let ourPublicKey = try self.keyManager.retrieveIdentity()

        let fingerprintNonce  = OccultaBundle.SecrecyContext.generateNonce()
        let senderFingerprint = OccultaBundle.SecrecyContext.fingerprint(
            for: ourPublicKey,
            nonce: fingerprintNonce
        )

        // Proactively generate a replenishment batch if stock is low.
        let outboundBatch: OccultaBundle.PrekeySyncBatch? = try {
            guard prekeyManager.needsReplenishment else { return nil }
            let batch = try prekeyManager.generateBatch()
            return OccultaBundle.PrekeySyncBatch(
                sequence: prekeyManager.currentSequence - 1, // generateBatch increments after
                prekeys: batch
            )
        }()

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

            return (OccultaBundle(version: OccultaBundle.currentVersion, secrecy: secrecy, ciphertext: ciphertext), outboundBatch)
        }

        // ── Long-term fallback path ──────────────────────────────────────
        let freshPrekeys = try prekeyManager.generateBatch()
        let freshBatch   = OccultaBundle.PrekeySyncBatch(
            sequence: prekeyManager.currentSequence - 1,
            prekeys:  freshPrekeys
        )

        return try self.fallback(
            message: message,
            recipientMaterial: recipientMaterial,
            ourPublicKey: ourPublicKey,
            fingerprintNonce: fingerprintNonce,
            senderFingerprint: senderFingerprint,
            outboundBatch: freshBatch
        )
    }

    // MARK: - Decryption

    /// Decrypt a bundle received from a contact.
    ///
    /// Sender identification is done by the caller (ContactManager) before this
    /// method is called, using `SecrecyContext.fingerprint(for:nonce:)`.
    ///
    /// The caller is responsible for storing `inboundBatch` by calling
    /// `syncPrekeyBatch(_:using:prekeyManager:)` on the sender's profile.
    ///
    /// On the forward secret path, the consumed prekey private key is deleted
    /// from the SE immediately after successful `open()`.
    ///
    /// - Parameter bundle: The ``OccultaBundle`` to decrypt.
    /// - Returns:
    ///   - `plaintext`: Decrypted payload, or `nil` if not addressed to us.
    ///   - `inboundBatch`: Sender's ``PrekeySyncBatch``. Caller syncs on sender's profile.
    /// - Throws: `CryptoKit` if GCM tag verification fails.
    func decryptForwardSecret(
        bundle: OccultaBundle
    ) throws -> (plaintext: Data?, inboundBatch: OccultaBundle.PrekeySyncBatch?) {

        let prekeyManager = Manager.PrekeyManager()
        let plaintext: Data?

        switch bundle.secrecy.mode {

        // ── Forward secret path ──────────────────────────────────────────
        case .forwardSecret:
            guard
                let prekeyID  = bundle.secrecy.prekeyID,
                let prekeySeq = bundle.secrecy.prekeySequence
            else {
                // Malformed — .forwardSecret must carry both prekeyID and prekeySequence.
                return (nil, nil)
            }

            // Reconstruct the full Prekey to get the correct SE tag.
            // publicKey is not needed here — we only need the tag for SE lookup.
            let prekeyStub = Prekey(id: prekeyID, sequence: prekeySeq, publicKey: Data())

            if let prekeyPrivateKey = prekeyManager.retrievePrivateKey(for: prekeyStub) {
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

                // Delete prekey private key from SE immediately.
                // This is the moment forward secrecy is established.
                prekeyManager.consume(prekey: prekeyStub)

                plaintext = decrypted

            } else {
                // Prekey already consumed or pruned.
                // Attempt long-term fallback — returns nil if GCM tag doesn't verify.
                plaintext = try? self.decryptLongTerm(bundle: bundle)
            }

        // ── Long-term fallback path ──────────────────────────────────────
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
        outboundBatch: OccultaBundle.PrekeySyncBatch?
    ) throws -> (bundle: OccultaBundle, outboundBatch: OccultaBundle.PrekeySyncBatch?) {

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

        return (OccultaBundle(version: OccultaBundle.currentVersion, secrecy: secrecy, ciphertext: ciphertext), outboundBatch)
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

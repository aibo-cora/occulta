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
    /// The caller is responsible for all SwiftData operations:
    /// - Fetching `contactPrekey` from the contact's profile before calling.
    /// - Removing that prekey from the contact's store after this call returns.
    /// - Persisting `outboundBatch` onto the contact's profile.
    ///
    /// This method only performs cryptographic operations on raw `Data`.
    /// It has no knowledge of SwiftData, Contact.Profile, or any persistent store.
    ///
    /// ## Forward secret path (`contactPrekey` is non-nil)
    /// ```
    /// 1. Generate throwaway ephemeral key pair (in memory, not SE)
    /// 2. sessionKey = HKDF(ECDH(ephemeralPriv, contactPrekey.publicKey))
    /// 3. AES-GCM.seal(message, using: sessionKey)
    /// 4. Build SecrecyContext { mode: .forwardSecret, ... }
    /// 5. Return (bundle, outboundBatch)
    /// ```
    ///
    /// ## Fallback path (`contactPrekey` is nil — prekeys exhausted)
    /// ```
    /// 1. sessionKey = HKDF(ECDH(ourLongTermSEKey, recipientMaterial))
    /// 2. AES-GCM.seal(message, using: sessionKey)
    /// 3. Build SecrecyContext { mode: .longTermFallback, ... }
    /// 4. Generate fresh prekeyBatch unconditionally — breaks the exhaustion cycle
    /// 5. Return (bundle, freshBatch)
    /// ```
    ///
    /// - Parameters:
    ///   - message:           Plaintext payload.
    ///   - contactPrekey:     Oldest prekey fetched from contact's profile by caller.
    ///                        Pass `nil` to trigger the fallback path.
    ///   - recipientMaterial: Recipient's long-term public key in x963 format.
    /// - Returns:
    ///   - `bundle`: Sealed ``OccultaBundle`` ready for transmission.
    ///   - `outboundBatch`: Fresh prekeys for caller to store on contact's profile.
    ///     `nil` if stock is healthy and no replenishment batch was generated.
    /// - Throws: `EncryptionError` or `CryptoKit` errors.
    func encryptForwardSecret(
        message: Data,
        contactPrekey: Prekey?,
        recipientMaterial: Data
    ) throws -> (bundle: OccultaBundle, outboundBatch: [Prekey]?) {

        let prekeyManager = Manager.PrekeyManager()

        // Retrieve our long-term public key — needed for the sender fingerprint
        // on both paths. Fail early if unavailable.
        let ourPublicKey = try self.keyManager.retrieveIdentity()

        // Compute nonce-bound sender fingerprint — identical structure on both paths.
        let fingerprintNonce   = OccultaBundle.SecrecyContext.generateNonce()
        let senderFingerprint  = OccultaBundle.SecrecyContext.fingerprint(for: ourPublicKey, nonce: fingerprintNonce)

        // Proactively generate a replenishment batch if our SE prekey stock is low.
        let outboundBatch: [Prekey]? = prekeyManager.needsReplenishment
            ? try prekeyManager.generateBatch()
            : nil

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
                let ciphertext = try AES.GCM.seal(message, using: sessionKey, nonce: AES.GCM.Nonce()).combined
            else {
                throw EncryptionError.sealFailed
            }

            // ephemeralPrivateKey goes out of scope here — forward secrecy established.

            let secrecy = OccultaBundle.SecrecyContext(
                mode:               .forwardSecret,
                ephemeralPublicKey: ephemeralPublicKeyData,
                prekeyID:           contactPrekey.id,
                fingerprintNonce:   fingerprintNonce,
                senderFingerprint:  senderFingerprint,
                prekeyBatch:        outboundBatch
            )

            let bundle = OccultaBundle(
                version:    OccultaBundle.currentVersion,
                secrecy:    secrecy,
                ciphertext: ciphertext
            )

            return (bundle, outboundBatch)
        }

        // ── Long-term fallback path ──────────────────────────────────────
        // Generate a full fresh batch unconditionally — breaks the exhaustion cycle.
        let freshBatch = try prekeyManager.generateBatch()

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
    /// Sender identification happens in the caller (ContactManager) before this
    /// method is called, using `SecrecyContext.fingerprint(for:nonce:)` against
    /// each stored contact's long-term public key.
    ///
    /// The caller is responsible for:
    /// - Identifying the sender via `bundle.secrecy.senderFingerprint` before calling.
    /// - Storing `inboundBatch` onto the sender's contact profile after this call.
    ///
    /// - Parameter bundle: The ``OccultaBundle`` received from a contact.
    /// - Returns:
    ///   - `plaintext`: Decrypted payload, or `nil` if not addressed to us.
    ///   - `inboundBatch`: Sender's fresh prekeys. Caller stores on sender's profile.
    /// - Throws: `CryptoKit` if GCM tag verification fails (tampering / corruption).
    func decryptForwardSecret(bundle: OccultaBundle) throws -> (plaintext: Data?, inboundBatch: [Prekey]?) {
        let prekeyManager = Manager.PrekeyManager()
        let plaintext: Data?

        switch bundle.secrecy.mode {
        case .forwardSecret:
            guard
                let prekeyID = bundle.secrecy.prekeyID
            else {
                // Malformed — .forwardSecret must carry a prekeyID.
                return (nil, nil)
            }

            if let prekeyPrivateKey = prekeyManager.retrievePrivateKey(for: prekeyID) {
                guard
                    let sessionKey = self.keyManager.createSharedSecret(ephemeralPrivateKey: prekeyPrivateKey, recipientMaterial: bundle.secrecy.ephemeralPublicKey)
                else {
                    return (nil, nil)
                }

                let box       = try AES.GCM.SealedBox(combined: bundle.ciphertext)
                let decrypted = try AES.GCM.open(box, using: sessionKey)

                // Delete the prekey private key from SE immediately after open().
                // This is the moment forward secrecy is established for this message.
                // The session key can never be reconstructed — the private half is gone.
                prekeyManager.consume(prekeyID: prekeyID)

                plaintext = decrypted

            } else {
                // Prekey already consumed (duplicate delivery) or absent.
                // Attempt long-term fallback — returns nil if GCM tag doesn't verify.
                plaintext = try? self.decryptLongTerm(bundle: bundle)
            }
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
        outboundBatch: [Prekey]?
    ) throws -> (bundle: OccultaBundle, outboundBatch: [Prekey]?) {

        guard
            let sessionKey = self.keyManager.createSharedSecret(using: recipientMaterial),
            let ciphertext = try AES.GCM.seal(message, using: sessionKey, nonce: AES.GCM.Nonce()).combined
        else {
            throw EncryptionError.keyDerivationFailed
        }

        let secrecy = OccultaBundle.SecrecyContext(
            mode:               .longTermFallback,
            ephemeralPublicKey: ourPublicKey,
            prekeyID:           nil,
            fingerprintNonce:   fingerprintNonce,
            senderFingerprint:  senderFingerprint,
            prekeyBatch:        outboundBatch
        )

        let bundle = OccultaBundle(
            version:    OccultaBundle.currentVersion,
            secrecy:    secrecy,
            ciphertext: ciphertext
        )

        return (bundle, outboundBatch)
    }

    private func decryptLongTerm(bundle: OccultaBundle) throws -> Data? {
        guard
            let sessionKey = self.keyManager.createSharedSecret(using: bundle.secrecy.ephemeralPublicKey)
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

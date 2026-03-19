//
//  OccultaBundle.swift
//  Occulta
//
//  Created by Yura on 3/14/26.
//

import Foundation
import CryptoKit

// MARK: - Bundle

/// A single-recipient encrypted bundle.
///
/// ## Layout
/// ```
/// OccultaBundle {
///     version    : Version           // typed version enum
///     secrecy    : SecrecyContext    // all key-exchange fields
///     ciphertext : Data              // AES-GCM combined (nonce || ct || tag)
/// }
/// ```
///
/// All forward secrecy concerns — mode, ephemeral key, prekey ID, fingerprint,
/// replenishment batch — are grouped in ``SecrecyContext``. If the bundle format
/// evolves, `ciphertext` and `version` remain untouched; only `SecrecyContext` grows.
struct OccultaBundle: Codable {

    // MARK: - Version

    static let currentVersion: Version = .v3fs

    enum Version: String, Codable {
        /// Long-term SE key used to encrypt messages. No forward secrecy.
        case v1
        /// Ephemeral key used to encrypt messages. Never shipped.
        case v2
        /// Complete forward secrecy via per-contact consumed prekey batches.
        case v3fs
    }

    // MARK: - Mode

    /// Which key derivation path was used to seal this bundle.
    enum Mode: String, Codable {

        /// Full forward secrecy via prekey path.
        ///
        /// Session key = HKDF(ECDH(senderEphemeralPriv, recipientPrekeyPub)).
        /// Recipient's prekey private key is deleted from SE on successful decrypt.
        case forwardSecret

        /// Prekey exhaustion fallback — no forward secrecy for this message.
        ///
        /// Session key = HKDF(ECDH(senderLongTermPriv, recipientLongTermPub)).
        /// Bundle always includes a fresh `PrekeySyncBatch` so the next message uses FS.
        case longTermFallback
    }

    // MARK: - PrekeySyncBatch

    /// A versioned batch of prekey public keys for a specific contact.
    ///
    /// Carries a monotonically increasing `sequence` so the recipient can
    /// decide whether to replace their stored prekeys or ignore the batch:
    ///
    /// ```
    /// incoming.sequence > stored.sequence  →  replace entirely, prune old SE keys
    /// incoming.sequence <= stored.sequence →  ignore (duplicate delivery)
    /// ```
    ///
    /// Each `Prekey` inside carries `contactID` — the recipient's identifier as
    /// known to the sender. This ensures SE tags on the sender's side remain
    /// scoped to this contact's pool.
    struct PrekeySyncBatch: Codable {

        /// Monotonically increasing batch generation number, per contact.
        let sequence: Int

        /// The prekey public keys in this batch.
        /// Each `Prekey` carries the same `contactID` and `sequence` as this batch.
        let prekeys: [Prekey]
    }

    // MARK: - SecrecyContext

    /// All key-exchange and forward-secrecy fields for a single bundle.
    ///
    /// ## Sender identification
    /// The recipient iterates contacts computing:
    /// ```
    /// SHA-256(contact.longTermPublicKey || fingerprintNonce)
    /// ```
    /// and compares against `senderFingerprint`. O(n) hash comparisons —
    /// no ECDH trial decryption. Sender is identified before decryption.
    ///
    /// A fresh `fingerprintNonce` per bundle prevents cross-bundle correlation.
    struct SecrecyContext: Codable {

        /// Which key derivation path was used.
        let mode: Mode

        /// Sender's ephemeral public key in x963 format (65 bytes).
        ///
        /// `.forwardSecret`:    throwaway key generated for this message only.
        /// `.longTermFallback`: sender's long-term identity public key.
        let ephemeralPublicKey: Data

        /// UUID of the recipient's prekey consumed to derive the session key.
        /// Non-nil only when `mode == .forwardSecret`.
        let prekeyID: String?

        /// Sequence number of the recipient's prekey that was consumed.
        ///
        /// Combined with `prekeyID` and the sender's `contactID` (which the
        /// recipient knows as their own identifier), the recipient reconstructs
        /// the exact SE tag: `"prekey.<contactID>.<prekeySequence>.<prekeyID>"`.
        /// Non-nil only when `mode == .forwardSecret`.
        let prekeySequence: Int?

        /// 16 random bytes, unique per bundle.
        ///
        /// Binds `senderFingerprint` to this bundle. Two bundles from the same
        /// sender produce different fingerprints — no cross-bundle linkability
        /// without already possessing the sender's long-term public key.
        let fingerprintNonce: Data

        /// SHA-256(senderLongTermPublicKey || fingerprintNonce).
        ///
        /// Allows O(n) sender identification without revealing identity to an
        /// observer who intercepts the bundle.
        let senderFingerprint: Data

        /// Sender's fresh prekeys for the recipient to store.
        ///
        /// Always included — even on the fallback path — so the next message
        /// can use the forward secret path.
        let prekeyBatch: PrekeySyncBatch?

        // MARK: - Fingerprint helpers

        /// Compute a nonce-bound sender fingerprint.
        ///
        /// - Parameters:
        ///   - publicKey: Sender's long-term public key in x963 format.
        ///   - nonce:     The bundle's `fingerprintNonce` (16 bytes).
        /// - Returns: SHA-256(publicKey || nonce) as 32 bytes.
        static func fingerprint(for publicKey: Data, nonce: Data) -> Data {
            var input = publicKey
            input.append(nonce)
            return Data(SHA256.hash(data: input))
        }

        /// Generate a cryptographically random fingerprint nonce (16 bytes).
        static func generateNonce() -> Data {
            var bytes = [UInt8](repeating: 0, count: 16)
            _ = SecRandomCopyBytes(kSecRandomDefault, 16, &bytes)
            return Data(bytes)
        }
    }

    // MARK: - Fields

    /// Protocol version.
    let version: Version

    /// All key-exchange and forward-secrecy fields.
    let secrecy: SecrecyContext

    /// AES-GCM combined payload (nonce(12B) || ciphertext || tag(16B)).
    let ciphertext: Data

    // MARK: - Serialisation

    func encoded() throws -> Data {
        try JSONEncoder().encode(self)
    }

    static func decoded(from data: Data) throws -> OccultaBundle {
        try JSONDecoder().decode(OccultaBundle.self, from: data)
    }

    // MARK: - UI helpers

    var isForwardSecret: Bool { self.secrecy.mode == .forwardSecret }

    var securityLabel: String {
        switch secrecy.mode {
        case .forwardSecret:    
            return "Forward Secret"
        case .longTermFallback: 
            return "Standard Encryption"
        }
    }
}

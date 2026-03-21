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
///     version           : Version        // typed version enum
///     secrecy           : SecrecyContext  // key-exchange fields — used as AAD
///     ciphertext        : Data            // AES-GCM combined (nonce || ct || tag)
///     fingerprintNonce  : Data            // 16 random bytes — routing metadata
///     senderFingerprint : Data            // SHA-256(senderPub || nonce) — routing metadata
/// }
/// ```
///
/// ## Why fingerprintNonce and senderFingerprint live at the bundle level
/// The recipient must identify the sender before decrypting anything.
/// Those two fields are therefore pre-decryption routing data — they cannot
/// live inside `SecrecyContext`, which would create a circular dependency:
///
/// ```
/// senderFingerprint → identify sender → get their long-term public key
///                   → derive session key → decrypt ciphertext
/// ```
///
/// `SecrecyContext` contains everything else and is passed as AAD to AES-GCM,
/// so its fields — including `prekeyBatch` — are authenticated by the GCM tag.
///
/// ## Tamper protection
/// `SecrecyContext` is serialised and passed as AAD to `AES.GCM.seal` / `AES.GCM.open`.
/// Any modification to any field inside it — including `prekeyBatch` — causes
/// `AES.GCM.open` to throw, closing the prekey substitution attack.
///
/// The routing fields (`fingerprintNonce`, `senderFingerprint`) are not in AAD.
/// Tampering with them makes the bundle undeliverable (sender identification fails)
/// but cannot expose plaintext or inject bad prekeys.
struct OccultaBundle: Codable {

    // MARK: - Version

    static let currentVersion: Version = .v3fs

    enum Version: String, Codable {
        /// Long-term SE key used to encrypt messages. No forward secrecy.
        case v1
        /// Ephemeral key used to encrypt messages. Never shipped.
        case v2
        /// Forward secrecy via per-contact consumed prekey batches.
        /// SecrecyContext authenticated as AAD — all context fields tamper-proof.
        case v3fs
    }

    // MARK: - Mode

    enum Mode: String, Codable {
        /// Full forward secrecy via prekey.
        ///
        /// Session key = HKDF(ECDH(senderEphemeralPriv, recipientPrekeyPub)).
        /// Recipient's prekey private key is deleted from SE on successful decrypt.
        case forwardSecret

        /// Prekey exhaustion fallback.
        ///
        /// Session key = HKDF(ECDH(senderLongTermPriv, recipientLongTermPub)).
        /// Bundle always includes a fresh `PrekeySyncBatch` so the next message uses FS.
        case longTermFallback
    }

    // MARK: - PrekeySyncBatch

    nonisolated
    struct PrekeySyncBatch: Codable {
        /// Monotonically increasing batch generation number, per contact.
        let sequence: Int
        /// Prekey public keys in this batch.
        let prekeys: [Prekey]
    }

    // MARK: - SecrecyContext

    /// All key-exchange fields for a single bundle.
    ///
    /// This struct is serialised as AAD and passed to `AES.GCM.seal` / `AES.GCM.open`.
    /// Every field here is authenticated by the GCM tag.
    ///
    /// Fields NOT in this struct (`fingerprintNonce`, `senderFingerprint`) live at
    /// the bundle level because they must be readable before the session key is derived.
    struct SecrecyContext: Codable {

        /// Which key derivation path was used.
        let mode: Mode

        /// Sender's ephemeral public key in x963 format (65 bytes).
        ///
        /// `.forwardSecret`:    throwaway key for this message only.
        /// `.longTermFallback`: sender's long-term identity public key.
        let ephemeralPublicKey: Data

        /// UUID of the recipient's prekey consumed to derive the session key.
        /// Non-nil only when `mode == .forwardSecret`.
        let prekeyID: String?

        /// Sequence number of the consumed prekey.
        /// Non-nil only when `mode == .forwardSecret`.
        let prekeySequence: Int?

        /// Sender's fresh prekeys for the recipient to store.
        ///
        /// Authenticated by the GCM tag — a substitution attack replacing these
        /// with attacker-controlled prekeys is detected at decryption time.
        let prekeyBatch: PrekeySyncBatch?

        // MARK: - Fingerprint helpers

        /// SHA-256(publicKey || nonce).
        static func fingerprint(for publicKey: Data, nonce: Data) -> Data {
            var input = publicKey
            input.append(nonce)
            
            return Data(SHA256.hash(data: input))
        }

        /// 16 cryptographically random bytes.
        static func generateNonce() -> Data {
            var bytes = [UInt8](repeating: 0, count: 16)
            _ = SecRandomCopyBytes(kSecRandomDefault, 16, &bytes)
            
            return Data(bytes)
        }
    }

    // MARK: - Fields

    let version: Version

    /// Key-exchange fields. Serialised as AAD — authenticated but not encrypted.
    let secrecy: SecrecyContext

    /// AES-GCM combined payload (nonce(12B) || ciphertext || tag(16B)).
    /// The GCM tag covers both ciphertext and `secrecy` (via AAD).
    let ciphertext: Data

    /// 16 random bytes, unique per bundle.
    /// Pre-decryption routing metadata — not in AAD.
    let fingerprintNonce: Data

    /// SHA-256(senderLongTermPublicKey || fingerprintNonce).
    /// Pre-decryption routing metadata — not in AAD.
    let senderFingerprint: Data

    // MARK: - Serialisation

    func encode() throws -> Data {
        try JSONEncoder().encode(self)
    }

    static func decode(from data: Data) throws -> OccultaBundle {
        try JSONDecoder().decode(OccultaBundle.self, from: data)
    }

    // MARK: - AAD
     
    /// Serialise `secrecy` for use as Additional Authenticated Data.
    ///
    /// Pass the result to `AES.GCM.seal(authenticating:)` on encrypt
    /// and `AES.GCM.open(authenticating:)` on decrypt.
    /// Any modification to any field in `SecrecyContext` will cause open to throw.
    /// Serialise `secrecy` as Additional Authenticated Data.
    ///
    /// `.sortedKeys` guarantees identical byte output regardless of which
    /// `JSONEncoder` instance is used or when this is called. Without sorted
    /// keys, two separate `JSONEncoder()` instances can produce different key
    /// orderings for the same struct, causing GCM authentication to fail.
    func secrecyAAD() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        
        return try encoder.encode(self.secrecy)
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

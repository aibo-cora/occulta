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
///     version           : Version        // typed version — included in AAD
///     secrecy           : SecrecyContext  // key-exchange fields — authenticated as AAD
///     ciphertext        : Data            // AES-GCM combined (nonce || ct || tag)
///     fingerprintNonce  : Data            // 16 random bytes — pre-decryption routing
///     senderFingerprint : Data            // SHA-256(senderPub || nonce) — routing
/// }
/// ```
///
/// ## Pre-decryption routing fields
/// `fingerprintNonce` and `senderFingerprint` cannot live inside `SecrecyContext`
/// because the recipient must identify the sender before deriving the session key:
/// ```
/// senderFingerprint → identify sender → get their long-term public key
///                   → derive session key → open ciphertext
/// ```
///
/// ## Tamper protection
/// `fullAAD()` serialises `version.rawValue + SecrecyContext` and passes it to
/// `AES.GCM.seal(authenticating:)` / `AES.GCM.open(authenticating:)`.
/// Any modification to `version`, `mode`, `ephemeralPublicKey`, `prekeyID`,
/// `prekeySequence`, or `prekeyBatch` causes `openBundle` to throw.
/// This closes the prekey substitution attack and the version-badge spoofing attack.
///
/// The routing fields (`fingerprintNonce`, `senderFingerprint`) are NOT authenticated.
/// Tampering with them makes the bundle undeliverable but cannot expose plaintext.
struct OccultaBundle: Codable {

    // MARK: - Errors

    enum BundleError: Error {
        /// `SecRandomCopyBytes` failed to produce entropy.
        /// Encryption must not proceed with a zero or predictable nonce.
        case entropyUnavailable
    }

    // MARK: - Version

    static let currentVersion: Version = .v3fs

    enum Version: String, Codable {
        /// Long-term SE key. No forward secrecy. Legacy only.
        case v1
        /// Ephemeral key path. Never shipped.
        case v2
        /// Per-contact consumed prekey batches. `SecrecyContext` + version authenticated as AAD.
        case v3fs
    }

    // MARK: - Mode

    enum Mode: String, Codable {
        /// Full forward secrecy.
        /// Session key = HKDF(ECDH(senderEphemeralPriv, recipientPrekeyPub)).
        /// Recipient's prekey private key is deleted from SE on successful decrypt.
        case forwardSecret

        /// Prekey exhaustion fallback.
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

    /// Key-exchange fields, authenticated as AAD.
    ///
    /// Every field here is covered by the GCM tag — modification causes `openBundle` to throw.
    /// The version enum is prepended to the AAD outside this struct (see `fullAAD()`).
    struct SecrecyContext: Codable {
        let mode:               Mode
        let ephemeralPublicKey: Data       // x963, 65 bytes
        let prekeyID:           String?    // non-nil only when mode == .forwardSecret
        let prekeySequence:     Int?       // non-nil only when mode == .forwardSecret
        let prekeyBatch:        PrekeySyncBatch?

        // MARK: Fingerprint helpers

        /// SHA-256(publicKey || nonce) — 32 bytes.
        static func fingerprint(for publicKey: Data, nonce: Data) -> Data {
            var input = publicKey
            input.append(nonce)
            
            return Data(SHA256.hash(data: input))
        }

        /// 16 cryptographically random bytes.
        ///
        /// - Throws: `BundleError.entropyUnavailable` if `SecRandomCopyBytes` fails.
        ///   Callers must not fall back to a hardcoded nonce — a static nonce
        ///   makes `senderFingerprint` identical across all bundles from the same sender.
        static func generateNonce() throws -> Data {
            var bytes = [UInt8](repeating: 0, count: 16)
            
            guard SecRandomCopyBytes(kSecRandomDefault, 16, &bytes) == errSecSuccess else {
                throw BundleError.entropyUnavailable
            }
            
            return Data(bytes)
        }
    }

    // MARK: - Fields

    /// Protocol version. Included in AAD — tampering causes `openBundle` to throw.
    let version: Version

    /// Key-exchange fields. Authenticated as AAD — not encrypted.
    let secrecy: SecrecyContext

    /// AES-GCM combined payload (nonce(12B) || ciphertext || tag(16B)).
    /// GCM tag covers both this field and `fullAAD()`.
    let ciphertext: Data

    /// 16 random bytes, unique per bundle. Pre-decryption routing — not in AAD.
    let fingerprintNonce: Data

    /// SHA-256(senderLongTermPublicKey || fingerprintNonce). Routing — not in AAD.
    let senderFingerprint: Data

    // MARK: - Serialisation

    func encoded() throws -> Data {
        try JSONEncoder().encode(self)
    }

    static func decoded(from data: Data) throws -> OccultaBundle {
        try JSONDecoder().decode(OccultaBundle.self, from: data)
    }

    // MARK: - AAD

    /// Full Additional Authenticated Data: `version.rawValue bytes || sortedKeys(SecrecyContext)`.
    ///
    /// Including `version` closes the version-badge spoofing attack (Finding 2):
    /// an attacker cannot flip `version` from `.v3fs` to `.v1` without causing
    /// `AES.GCM.open` to throw.
    ///
    /// `.sortedKeys` is mandatory — without it, two `JSONEncoder` instances can produce
    /// different key orderings for the same struct, causing spurious `authenticationFailure`.
    func fullAAD() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        
        var aad = self.version.rawValue.data(using: .utf8)!
        aad.append(contentsOf: try encoder.encode(self.secrecy))
        
        return aad
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

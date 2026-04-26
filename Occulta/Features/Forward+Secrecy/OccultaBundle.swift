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
/// ## Wire layout
/// ```
/// OccultaBundle {
///     version           : Version        // typed version — included in AAD
///     secrecy           : SecrecyContext  // minimal key-exchange fields — AAD
///     ciphertext        : Data            // AES-GCM(SealedPayload) — see below
///     fingerprintNonce  : Data            // 16 random bytes — pre-decryption routing
///     senderFingerprint : Data            // SHA-256(senderPub || nonce) — routing
/// }
///
/// SealedPayload (encrypted, inside ciphertext) {
///     message     : Data               // plaintext message bytes
///     prekeyBatch : PrekeySyncBatch?   // sender's new prekeys, or nil
/// }
/// ```
///
/// ## Why the batch lives in the ciphertext, not in SecrecyContext
///
/// `PrekeySyncBatch` used to sit in `SecrecyContext` (AAD — authenticated but visible).
/// Every observer could read the batch: prekey public keys, their count, and every
/// `Prekey.contactID` — the sender's internal identifier for the recipient. That
/// identifier is stable and non-rotating, leaking the relationship graph to any passive
/// interceptor even with no ability to decrypt the message.
///
/// Moving the batch into `SealedPayload` encrypts it with the same session key and GCM
/// tag as the message itself. Zero additional nonces, zero additional operations,
/// zero size cost beyond the batch JSON. An observer now sees only:
///   - `mode` (forwardSecret or longTermFallback)
///   - `ephemeralPublicKey` (65 bytes, required for ECDH, inherently visible)
///   - `prekeyID` (needed to look up our SE private key before decryption)
///
/// `prekeySequence` has been removed. It was written into `SecrecyContext` but never
/// read during decryption — the sequence is already embedded in the stored `Prekey`
/// blob retrieved via `prekeyID`. Removing it reduces AAD size and eliminates one
/// metadata field visible to observers.
///
/// ## Tamper protection
/// `computeAdditionalAuthentication()` = `version.rawValue || sortedKeys(SecrecyContext)`.
/// Any modification to `version`, `mode`, `ephemeralPublicKey`, or `prekeyID`
/// causes `AES.GCM.open` to throw.
///
/// ## Pre-decryption routing
/// `fingerprintNonce` and `senderFingerprint` are not in the AAD and not encrypted.
/// They must be readable before any key is derived. Tampering with them makes the
/// bundle undeliverable — no contact's fingerprint will match — but cannot expose
/// plaintext or inject bad prekeys.
struct OccultaBundle: Codable {

    // MARK: - Errors

    enum BundleError: Error {
        /// `SecRandomCopyBytes` failed to produce entropy.
        /// Encryption must not proceed with a zero or predictable nonce.
        case entropyUnavailable
        /// Bundle carries a `Version` string this build does not recognise.
        /// Surfaced to the UI as "requires a newer version of Occulta."
        case unsupportedVersion
        /// Bundle carries a `Mode` string this build does not recognise.
        /// Surfaced to the UI as "requires a newer version of Occulta."
        case unsupportedMode
    }

    // MARK: - Version

    static let currentVersion: Version = .v3fs

    /// ⚠️ Adding a new case here is a **wire-format-breaking change** for older
    /// builds already in the field. An old `Version` enum without the new case
    /// throws `DecodingError.dataCorrupted` on decode, killing the bundle
    /// silently. Do not add cases to introduce new features — instead, put the
    /// feature's discriminator *inside* the encrypted `SealedPayload` via its
    /// own optional sub-envelope (see `SealedPayload.identityChallenge`) and
    /// keep the wire `version` at a value old builds already understand. See
    /// the Exchange.swift comment for the same pattern applied to key-exchange
    /// messages.
    enum Version: String, Codable {
        /// Long-term SE key. No forward secrecy. Legacy only.
        case v1
        /// Ephemeral key path. Never shipped.
        case v2
        /// Per-contact consumed prekey batches. `SecrecyContext` + version authenticated as AAD.
        case v3fs
        /// A version string this build does not understand.
        /// Never written to the wire — only produced by `init(from:)` when an
        /// inbound bundle carries an unknown raw value. Decryption aborts
        /// before AAD computation; AAD would fail anyway since the original
        /// version string is lost.
        case unsupported

        init(from decoder: Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            self = Version(rawValue: raw) ?? .unsupported
        }
    }

    // MARK: - Mode

    /// ⚠️ Same rule as `Version`: adding a case here breaks existing builds.
    /// Route new behaviour through a dedicated optional envelope on
    /// `SealedPayload` (e.g. `identityChallenge`), not new modes.
    enum Mode: String, Codable {
        /// Full forward secrecy.
        /// Session key = HKDF(ECDH(senderEphemeralPriv, recipientPrekeyPub)).
        /// Recipient's prekey private key deleted from SE on successful open.
        case forwardSecret

        /// Prekey exhaustion fallback.
        /// Session key = HKDF(ECDH(senderLongTermPriv, recipientLongTermPub)).
        /// Bundle always carries a fresh PrekeySyncBatch (inside ciphertext)
        /// so the next message can use the forward secret path.
        ///
        /// Identity challenges also ride this mode — they are long-term ECDH
        /// bundles with an `IdentityChallengeEnvelope` inside the payload.
        case longTermFallback

        /// Mode this build does not understand. Same semantics as `Version.unsupported`.
        case unsupported

        init(from decoder: Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            self = Mode(rawValue: raw) ?? .unsupported
        }
    }

    // MARK: - WirePrekey
     
    /// The wire representation of a prekey — public key only, no `contactID`.
    ///
    /// `Prekey` (the internal type) carries `contactID` so we can reconstruct
    /// the SE tag `"prekey.<contactID>.<sequence>.<id>"` when decrypting.
    /// That identifier is the sender's internal reference to the recipient and
    /// must never travel on the wire — it would leak the relationship graph to
    /// any passive observer.
    ///
    /// The recipient reconstructs the full `Prekey` by filling in their own
    /// local identifier as `contactID` when storing the batch.
    nonisolated
    struct WirePrekey: Codable, Equatable {
        /// Unique identifier for this prekey within its batch.
        let id:        String
        /// x963 uncompressed P-256 public key (65 bytes).
        let publicKey: Data
    }
    
    // MARK: - ShardOperation

    /// A shard-protocol operation carried inside `SealedPayload`.
    ///
    /// Using a struct with a `kind` discriminator rather than an enum keeps
    /// Codable synthesis simple and avoids associated-value encoding quirks.
    ///
    /// Field usage by kind:
    ///
    /// | kind                | attribute | attrID | attrIDs | replacesID |
    /// |---------------------|-----------|--------|---------|------------|
    /// | .distribute         | ✅        | —      | —       | optional   |
    /// | .acknowledge        | —         | ✅     | —       | —          |
    /// | .revoke             | —         | ✅     | —       | —          |
    /// | .handback           | ✅        | —      | —       | —          |
    /// | .notFound           | —         | ✅     | —       | —          |
    /// | .returnAcknowledged | —         | —      | ✅      | —          |
    ///
    /// Old builds that don't know about shards silently ignore `shardOperation`
    /// and render `SealedPayload.message` as regular text — same pattern as
    /// `identityChallenge`.
    nonisolated
    struct ShardOperation: Codable {
        enum Kind: String, Codable {
            /// Owner → trustee: here is your shard.
            case distribute
            /// Trustee → owner: shard received and stored.
            case acknowledge
            /// Owner → trustee: discard this shard (PEK rotated or trustee removed).
            case revoke
            /// Trustee → owner: here is your shard back (auto-return on key change).
            ///
            /// Named `.handback` rather than `.return` (a Swift reserved word) or
            /// `.respond` (which implied a prior `.request` that no longer exists).
            case handback
            /// Trustee → owner: I don't have a shard with this ID.
            case notFound
            /// Owner → trustee: I received these shards — you may delete your custody rows.
            case returnAcknowledged
            /// A kind this build does not understand. Decoded from unknown raw values.
            /// The handler skips it silently so bundles from newer builds don't break older ones.
            case unsupported

            init(from decoder: Decoder) throws {
                let raw = try decoder.singleValueContainer().decode(String.self)
                self = Kind(rawValue: raw) ?? .unsupported
            }
        }

        let kind: Kind
        /// The `SignedAttribute` shard payload. Non-nil for `.distribute` and `.handback`.
        let attribute: SignedAttribute?
        /// The target shard's `SignedAttribute.id`. Non-nil for `.acknowledge`, `.revoke`,
        /// and `.notFound`.
        let attrID: UUID?
        /// Multiple shard IDs. Non-nil for `.returnAcknowledged` — carries every
        /// `SignedAttribute.id` the owner has safely stored, so the trustee can
        /// delete the corresponding `CustodyShard` rows in one pass.
        let attrIDs: [UUID]?
        /// For `.distribute`: the `SignedAttribute.id` of an older shard this supersedes.
        /// Trustee apps discard the old shard on receipt. Nil on first distribution.
        let replacesID: UUID?

        init(
            kind: Kind,
            attribute: SignedAttribute? = nil,
            attrID: UUID? = nil,
            attrIDs: [UUID]? = nil,
            replacesID: UUID? = nil
        ) {
            self.kind       = kind
            self.attribute  = attribute
            self.attrID     = attrID
            self.attrIDs    = attrIDs
            self.replacesID = replacesID
        }
    }

    // MARK: - SealedPayload

    /// The plaintext structure sealed inside `ciphertext`.
    ///
    /// Both `message` and `prekeyBatch` are encrypted and authenticated together
    /// by a single AES-GCM operation. No additional nonces or operations needed.
    ///
    /// Keeping the batch here rather than in `SecrecyContext` (AAD) means:
    /// - Prekey public keys are never visible to a passive observer.
    /// - `WirePrekey.contactID` (stripped at the type level) cannot leak.
    /// - Batch size gives no metadata beyond total bundle size.
    nonisolated
    struct SealedPayload: Codable {
        /// The message plaintext.
        ///
        /// For regular messages this is the user's text or file basket.
        /// For identity challenges (non-nil `identityChallenge`) this is a
        /// human-readable fallback string shown by old builds that don't
        /// know about the identity-challenge envelope.
        let message: Data
        /// The sender's fresh prekeys for the recipient to store, or nil.
        /// Non-nil on the fallback path (always), and on the FS path when
        /// the sender's SE stock for this contact is below the replenishment threshold.
        let prekeyBatch: PrekeySyncBatch?

        /// Identity-challenge sub-envelope. `nil` means a regular message —
        /// routing to `IdentityChallenge.Manager` happens iff this is non-nil.
        ///
        /// Bundling the phase discriminator, binary payload, and optional
        /// context note into a single field makes "kind and payload travel
        /// together" a type-level invariant: a single optional unwrap tells
        /// us everything the router needs. Old builds without this key
        /// silently ignore it and render `message` as regular text.
        ///
        /// Added in v1.4.0. Future per-feature envelopes (Document Signing,
        /// etc.) should sit alongside as their own optional fields rather
        /// than extending this one.
        let identityChallenge: IdentityChallengeEnvelope?

        /// SSS shard-protocol operations. `nil` means a regular message.
        ///
        /// A list rather than a single operation so that multiple shards (e.g. from
        /// several vault entries) can be returned to an owner in one bundle. Old builds
        /// silently ignore unknown fields and render `message` as text. Shard traffic
        /// always uses `.longTermFallback` mode so old builds decode the outer bundle.
        ///
        /// Added in v1.6.0.
        let shardOperations: [ShardOperation]?

        init(
            message: Data,
            prekeyBatch: PrekeySyncBatch? = nil,
            identityChallenge: IdentityChallengeEnvelope? = nil,
            shardOperations: [ShardOperation]? = nil
        ) {
            self.message           = message
            self.prekeyBatch       = prekeyBatch
            self.identityChallenge = identityChallenge
            self.shardOperations   = shardOperations
        }

        /// A versioned batch of the sender's prekey public keys.
        ///
        /// Encrypted inside `SealedPayload.ciphertext` — never visible to observers.
        nonisolated
        struct PrekeySyncBatch: Codable {
            let generatedAt: Date
            /// Wire representation of the prekey public keys in this batch.
            let prekeys: [WirePrekey]
        }
    }

    // MARK: - SecrecyContext

    /// Key-exchange fields, authenticated as AAD.
    ///
    /// Every field here is covered by the GCM tag — modification causes `openBundle` to throw.
    /// The version enum is prepended to the AAD outside this struct (see `computeAdditionalAuthentication()`).
    struct SecrecyContext: Codable {
        /// Which key derivation path was used.
        let mode: Mode
 
        /// Sender's ephemeral public key in x963 format (65 bytes).
        /// `.forwardSecret`: throwaway key for this message only.
        /// `.longTermFallback`: sender's long-term identity public key.
        let ephemeralPublicKey: Data
 
        /// UUID of the recipient's prekey used to derive the session key.
        /// Non-nil only when `mode == .forwardSecret`.
        /// The recipient looks this up in their `ownPrekeys` store to reconstruct
        /// the SE tag and retrieve the corresponding private key.
        let prekeyID: String?

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
            try self._generateNonce { bytes, count in
                SecRandomCopyBytes(kSecRandomDefault, count, bytes)
            }
        }

        /// Testable entry point — production code delegates here via `generateNonce()`.
        /// Inject a failing provider to verify `entropyUnavailable` is thrown.
        internal static func _generateNonce(provider: (UnsafeMutablePointer<UInt8>, Int) -> Int32) throws -> Data {
            var bytes = [UInt8](repeating: 0, count: 16)
            
            guard provider(&bytes, 16) == errSecSuccess else {
                throw BundleError.entropyUnavailable
            }
            
            return Data(bytes)
        }
    }

    // MARK: - Fields
     
    /// Protocol version. Included in AAD — tampering causes `open` to throw.
    let version: Version
 
    /// Minimal key-exchange fields. Authenticated as AAD — not encrypted.
    /// An observer can read `mode`, `ephemeralPublicKey`, and `prekeyID` only.
    let secrecy: SecrecyContext
 
    /// AES-GCM combined payload: nonce(12B) || JSON(SealedPayload) || tag(16B).
    /// The GCM tag covers both this ciphertext and `computeAdditionalAuthentication()`.
    /// `SealedPayload` contains the message AND any `PrekeySyncBatch`.
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
    static func computeAdditionalAuthentication(version: OccultaBundle.Version, secrecy: SecrecyContext) throws -> Data {
        let version = version.rawValue.data(using: .utf8)!
        let secrecy = try Self.encoder.encode(secrecy)
        let together = version + secrecy
        
        return together
    }
    /// Encoder for computing additional authentication data.
    /// Using `.sortedKeys` to make results deterministic.
    static private let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = .sortedKeys
        
        return e
    }()

    // MARK: - UI helpers

    var isForwardSecret: Bool { self.secrecy.mode == .forwardSecret }

    var securityLabel: String {
        switch secrecy.mode {
        case .forwardSecret:    
            return "Forward Secret"
        case .longTermFallback: 
            return "Standard Encryption"
        case .unsupported:      
            return "Unsupported"
        }
    }
}

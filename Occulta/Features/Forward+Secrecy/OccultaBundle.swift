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
        /// Wire data contains a structural violation (e.g. duplicate TLV section).
        case malformedBundle
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
        /// Binary wire format — eliminates base64 inflation at all three serialisation layers.
        /// First shipped in app version 1.8.2. See Docs/Features/Bundle/SPEC.md.
        case v4
        /// Capability watermark: contact is running app version ≥ 1.9.0 and can process
        /// group bundles (`Mode.group`). Never written to the bundle `version` field on the
        /// wire — stored only in `Contact.Profile.maxBundleVersion` as byte 0x05.
        /// Group bundles are JSON-encoded with `version: .v4`; this case exists solely so
        /// `resolveTargetVersion` can signal group eligibility to the caller.
        case groupCapable
        /// Capability watermark: contact's build understands the per-recipient shard
        /// distribution fields on `RecipientPayload` (shardOperations / custodyManifest /
        /// expectedShards). Never written to the wire `version` field — stored only in
        /// `Contact.Profile.maxBundleVersion` as byte 0x06. Group bundles carrying
        /// per-recipient shard content still wire-encode with `version: .v4`; this case
        /// exists solely so `resolveTargetVersion` can signal shard-distribution
        /// eligibility to the caller.
        case groupShardCapable
        /// Capability watermark: contact's build signs the ephemeral key on FS-mode
        /// group messages (`RecipientPayload.senderEphemeralSignature`), closing the
        /// gap where `senderProof` alone doesn't authenticate the sender for FS mode
        /// (see finding #8, SecurityReview2026-07-24). Never written to the wire
        /// `version` field — stored only in `Contact.Profile.maxBundleVersion` as
        /// byte 0x07.
        case senderSignatureCapable
        /// A version string this build does not understand.
        /// Never written to the wire — only produced by `init(from:)` when an
        /// inbound bundle carries an unknown raw value. Decryption aborts
        /// before AAD computation; AAD would fail anyway since the original
        /// version string is lost.
        case unsupported

        /// The minimum app version that can read this wire format.
        /// `nil` means the case is not a real wire format (legacy, unsupported).
        var minimumAppVersion: String? {
            switch self {
            case .v3fs:             return "0.0.0"
            case .v4:               return "1.8.2"
            case .groupCapable:     return "1.9.0"
            case .groupShardCapable: return "1.9.1"
            default:                return nil
            }
        }

        /// The binary wire byte for this version. Used by WireHandle for encoding/decoding.
        /// `nil` for cases that are JSON-only or not real wire formats.
        var wireByte: UInt8? {
            switch self {
            case .v4:                return 0x04
            case .groupCapable:      return 0x05
            case .groupShardCapable: return 0x06
            default:                 return nil
            }
        }

        /// True when this contact's app version supports group bundles.
        var supportsGroups: Bool { self == .groupCapable || self == .groupShardCapable }

        /// Position in `known` — lower index = newer/higher capability tier.
        /// `nil` for non-tiered cases (`.v1`, `.v2`, `.unsupported`) that never come
        /// from `max(forAppVersion:)`.
        private var rank: Int? { Self.known.firstIndex(of: self) }

        /// True if this tier is at least as capable as `other` — i.e. `other`'s
        /// feature set is a subset of this one's. Adding a new tier above `other` in
        /// `known` extends this automatically; no separate case list to maintain,
        /// unlike `supportsGroups` above.
        func isAtLeast(_ other: Version) -> Bool {
            guard let mine = self.rank, let theirs = other.rank else { return false }
            return mine <= theirs
        }

        /// All real capability levels, descending — `max(forAppVersion:)` returns the
        /// first entry whose `minimumAppVersion` the given app version satisfies, so
        /// order matters: the highest tier a contact could possibly qualify for must
        /// be checked first.
        private static let known: [Version] = [
            .groupShardCapable, // 1.9.1+  — per-recipient shard fields on RecipientPayload
            .groupCapable,      // 1.9.0+  — can process group bundles (Mode.group)
            .v4,                // 1.8.2+  — binary wire format (no base64 inflation)
            .v3fs,              // 0.0.0+  — per-contact prekeys, floor/fallback tier
        ]

        /// The highest capability level a contact running `appVersion` can handle.
        static func max(forAppVersion appVersion: String) -> Version {
            Self.known.first {
                guard let min = $0.minimumAppVersion else { return false }
                return appVersion.compare(min, options: .numeric) != .orderedAscending
            } ?? .v3fs
        }

        init(from decoder: Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            self = Version(rawValue: raw) ?? .unsupported
        }
    }

    // MARK: - Mode

    /// Each mode encodes exactly one key derivation path — no ambiguity, no
    /// fallback on the receive side. Adding a case here makes old builds decode
    /// the bundle as `.unsupported`, producing `BundleError.unsupportedMode`
    /// (explicit, actionable) rather than a cryptic authentication failure.
    enum Mode: String, Codable {
        /// Full forward secrecy + hybrid PQ.
        /// Session key = HKDF(ECDH(senderEphemeralPriv, recipientPrekeyPub) ∥ ML-KEM).
        /// Recipient's prekey private key deleted from SE on successful open.
        case forwardSecret

        /// Forward secrecy, classical-only (no ML-KEM).
        /// Session key = HKDF(ECDH(senderEphemeralPriv, recipientPrekeyPub)).
        /// Used when the recipient's ML-KEM material is absent or corrupt.
        /// Old builds decode this as `.unsupported`.
        case forwardSecretNoPQ

        /// Prekey exhaustion fallback + hybrid PQ.
        /// Session key = HKDF(ECDH(senderLongTermPriv, recipientLongTermPub) ∥ ML-KEM).
        /// Bundle always carries a fresh PrekeySyncBatch (inside ciphertext)
        /// so the next message can use the forward secret path.
        ///
        /// Identity challenges also ride this mode — they are long-term ECDH
        /// bundles with an `IdentityChallengeEnvelope` inside the payload.
        case longTermFallback

        /// Prekey exhaustion fallback, classical-only (no ML-KEM).
        /// Session key = HKDF(ECDH(senderLongTermPriv, recipientLongTermPub)).
        /// Used when the recipient's ML-KEM material is absent or corrupt.
        /// Old builds decode this as `.unsupported`.
        case longTermNoPQ

        /// Group message. One shared ciphertext encrypted with a random session key;
        /// session key wrapped once per recipient in `GroupEnvelope.recipients`.
        /// Each `Recipient.secrecyContext.mode` signals the per-recipient key path
        /// (`.forwardSecret` or `.longTermFallback`).
        /// Old builds decode this as `.unsupported` → `BundleError.unsupportedMode`.
        case group

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
    /// Batching multiple operations of the same kind is done via the outer
    /// `[ShardOperation]` array on `SealedPayload` — each operation carries
    /// exactly one shard's data, so no plural-ID fields are needed here.
    ///
    /// Field usage by kind:
    ///
    /// | kind        | attribute          | attributeID            |
    /// |-------------|--------------------|------------------------|
    /// | .distribute | ✅ new shard       | —                      |
    /// | .replace    | ✅ new shard       | ✅ old shard to delete |
    /// | .handback   | ✅ shard returned  | —                      |
    ///
    /// Old builds that don't know about shards silently ignore `shardOperations`
    /// and render `SealedPayload.message` as regular text — same pattern as
    /// `identityChallenge`.
    nonisolated
    struct ShardOperation: Codable {
        enum Kind: String, Codable {
            /// Owner → trustee: here is your shard (first distribution).
            case distribute
            /// Owner → trustee: here is a replacement shard; discard `attributeID`.
            case replace
            /// Trustee → owner: here is your shard back (auto-return on key change).
            ///
            /// Named `.handback` rather than `.return` (a Swift reserved word).
            case handback
            /// A kind this build does not understand. Decoded from unknown raw values.
            /// The handler skips it silently so bundles from newer builds don't break older ones.
            case unsupported

            init(from decoder: Decoder) throws {
                let raw = try decoder.singleValueContainer().decode(String.self)
                self = Kind(rawValue: raw) ?? .unsupported
            }
        }

        let kind: Kind
        /// The `SignedAttribute` shard payload. Non-nil for `.distribute`, `.replace`, and `.handback`.
        let attribute: SignedAttribute?
        /// A single shard ID. Non-nil for `.replace` (old shard to delete).
        let attributeID: UUID?

        init(
            kind: Kind,
            attribute: SignedAttribute? = nil,
            attributeID: UUID? = nil
        ) {
            self.kind        = kind
            self.attribute   = attribute
            self.attributeID = attributeID
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

        /// IDs of all custody shards this sender currently holds for the recipient.
        /// `nil` = old build (no-op for receiver). `[]` = holds nothing.
        /// Trustee → owner direction only. Added in v1.7.0.
        let custodyManifest: [UUID]?

        /// IDs the owner expects this trustee to hold. Absence of an ID is an implicit
        /// revoke signal for same-fingerprint shards. `nil` = old build (no-op).
        /// Owner → trustee direction only. Added in v1.7.0.
        let expectedShards: [UUID]?

        /// Sender's app version string (e.g. `"1.8.2"`). Receivers derive the contact's
        /// `maxBundleVersion` from this and store it encrypted on the contact record.
        /// `nil` means the sender is on a build older than 1.8.2. Added in v1.8.2.
        let appVersion: String?

        /// HMAC-SHA256(sessionKey, senderLongTermPublicKey). Authenticates sender identity
        /// inside the GCM-protected ciphertext, preventing any party (including other group
        /// members) from re-attributing an intercepted bundle to a different sender by
        /// replacing the cleartext `senderFingerprint` / `fingerprintNonce` fields.
        ///
        /// The session key is the sole keying material — only the actual sender can produce
        /// this value, and only authenticated recipients can verify it. `nil` on bundles
        /// from builds older than 1.9.0. Added in v1.9.0.
        let senderProof: Data?

        /// The stable group UUID this bundle was sealed for. Stored inside the encrypted
        /// payload so the receiver can match the bundle to a local `Group` record without
        /// the group identity being visible in the cleartext `GroupEnvelope`.
        /// `nil` on non-group bundles and builds older than 1.9.0. Added in v1.9.0.
        let groupID: UUID?

        init(
            message: Data,
            prekeyBatch: PrekeySyncBatch? = nil,
            identityChallenge: IdentityChallengeEnvelope? = nil,
            shardOperations: [ShardOperation]? = nil,
            custodyManifest: [UUID]? = nil,
            expectedShards: [UUID]? = nil,
            appVersion: String? = nil,
            senderProof: Data? = nil,
            groupID: UUID? = nil
        ) {
            self.message           = message
            self.prekeyBatch       = prekeyBatch
            self.identityChallenge = identityChallenge
            self.shardOperations   = shardOperations
            self.custodyManifest   = custodyManifest
            self.expectedShards    = expectedShards
            self.appVersion        = appVersion
            self.senderProof       = senderProof
            self.groupID           = groupID
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
        /// `.longTermFallback`: empty `Data()` — never the sender's long-term key;
        /// the recipient already has it, and putting it in cleartext AAD would
        /// leak the sender's identity to any passive observer.
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

    // MARK: - GroupEnvelope

    /// Outer group envelope — present only when `secrecy.mode == .group`.
    ///
    /// `blind` replaces the stable group UUID in the cleartext TLV section.
    /// It is included in both the outer ciphertext AAD and each per-recipient
    /// `wrappedPayload` AAD to preserve cross-group replay resistance, while
    /// preventing passive observers from clustering bundles by group identity.
    /// The stable `groupID` is stored inside the encrypted `SealedPayload` only.
    nonisolated
    struct GroupEnvelope: Codable {
        /// Format version. `1` = trial-decryption slot-finding (no cleartext fingerprints).
        /// Receivers that encounter an unknown version must reject the bundle.
        let version:    UInt8
        /// HMAC-SHA256(key: groupID.rawBytes, msg: blindNonce). Fresh per bundle.
        let blind:      Data
        /// 16 random bytes. Combined with a stored group's UUID to verify `blind`.
        let blindNonce: Data
        let recipients: [Recipient]

        init(version: UInt8 = 1, blind: Data, blindNonce: Data, recipients: [Recipient]) {
            self.version    = version
            self.blind      = blind
            self.blindNonce = blindNonce
            self.recipients = recipients
        }
    }

    /// One entry per group member in the active depth layer at send time.
    nonisolated
    struct Recipient: Codable {
        /// Per-recipient key exchange fields. `mode` is `.forwardSecret` or
        /// `.longTermFallback`; never `.group` or `.unsupported`.
        let secrecyContext: SecrecyContext
        /// AES-GCM(JSON(RecipientPayload), wrappingKey, AAD: blind).
        /// The receiver finds their slot by trial-decryption — no cleartext
        /// identity hint is included, so an observer cannot confirm membership.
        let wrappedPayload: Data
    }

    /// Plaintext sealed inside each `Recipient.wrappedPayload`.
    /// Only the intended recipient can derive `wrappingKey` to open it.
    ///
    /// The five shard-related fields are always populated by a `.groupShardCapable`
    /// sender, padded to a fixed per-bundle tier (`ShardPadding.tier(for:)`) so every
    /// recipient's encoded payload is the same length regardless of whether they
    /// carry real shard content — otherwise ciphertext length alone would reveal
    /// which group member is an SSS trustee (`GroupEnvelope`/`wrappedPayload` travel
    /// as a cleartext JSON TLV block; see `WireHandle.encode(_:)`). Filler
    /// `shardOperations` entries carry `kind == .unsupported` (already ignored by
    /// `ShardCustodyManager.handleInbound`'s dispatch); filler `custodyManifest`/
    /// `expectedShards` entries are random UUIDs beyond the real count fields.
    nonisolated
    struct RecipientPayload: Codable {
        /// 32-byte random session key that decrypts the shared outer ciphertext.
        let sessionKey: Data
        /// Sender's fresh prekeys for this recipient, or nil when stock is healthy
        /// and the forward-secret path was used. Mirrors the single-recipient
        /// replenishment logic — same threshold, same `PrekeySyncBatch` type.
        let prekeyBatch: SealedPayload.PrekeySyncBatch?
        /// Fixed-size (tier-padded), always present. Real ops first; entries beyond
        /// the real count carry `kind == .unsupported` filler.
        let shardOperations: [ShardOperation]
        /// Fixed-size (tier-padded), always present. Only the first
        /// `custodyManifestCount` entries are real shard IDs.
        let custodyManifest: [UUID]
        let custodyManifestCount: Int
        /// Fixed-size (tier-padded), always present. Only the first
        /// `expectedShardsCount` entries are real shard IDs.
        let expectedShards: [UUID]
        let expectedShardsCount: Int
        /// Whether the sender actually attempted to build `custodyManifest` and
        /// `expectedShards` for this recipient — always both together, never one
        /// without the other (see `ContactManager.encryptGroupBundle`).
        ///
        /// Needed because `custodyManifestCount`/`expectedShardsCount == 0` is
        /// genuinely ambiguous on its own: it means either "sender attempted this
        /// and found nothing" (a real, meaningful signal — e.g. "I hold zero of
        /// your shards", or an intentional revoke-all) or "sender never attempted
        /// this at all" (ineligible member, or a locked vault at send time — no
        /// signal was intended). Those two cases must be told apart: a real empty
        /// list has to reach `ShardCustodyManager.processInboundManifest`/
        /// `processExpectedShards` (the receive side reads a `nil` array as "skip
        /// verification" and a real, possibly-empty array as "process it" — see
        /// `ContactManager.openGroup`), while a not-attempted list must not.
        /// Without this flag both cases decode to the same `count == 0`, so the
        /// receiver would silently skip real revoke-all/loss-detection signals
        /// exactly as often as it correctly skips irrelevant ones.
        let shardMetadataAttempted: Bool

        /// ECDSA signature over `Recipient.secrecyContext.ephemeralPublicKey`, signed
        /// with the sender's long-term identity key. Populated only for FS-mode
        /// recipients (`.forwardSecret`/`.forwardSecretNoPQ`) — fallback mode's
        /// wrapping-key ECDH already requires the sender's real long-term private key,
        /// so it doesn't need this. `nil` on bundles from builds older than 1.10.0, or
        /// for fallback-mode recipients. See finding #8, SecurityReview2026-07-24: FS
        /// mode's session key never involves the sender's long-term identity, so
        /// without this, `senderProof` alone can be satisfied without holding the
        /// real sender's private key. Added in v1.10.0.
        let senderEphemeralSignature: Data?

        init(
            sessionKey: Data,
            prekeyBatch: SealedPayload.PrekeySyncBatch? = nil,
            shardOperations: [ShardOperation] = [],
            custodyManifest: [UUID] = [],
            custodyManifestCount: Int = 0,
            expectedShards: [UUID] = [],
            expectedShardsCount: Int = 0,
            shardMetadataAttempted: Bool = false,
            senderEphemeralSignature: Data? = nil
        ) {
            self.sessionKey               = sessionKey
            self.prekeyBatch              = prekeyBatch
            self.shardOperations          = shardOperations
            self.custodyManifest          = custodyManifest
            self.custodyManifestCount     = custodyManifestCount
            self.expectedShards           = expectedShards
            self.expectedShardsCount      = expectedShardsCount
            self.shardMetadataAttempted   = shardMetadataAttempted
            self.senderEphemeralSignature = senderEphemeralSignature
        }

        // Custom decoding: a payload from a pre-groupShardCapable sender simply
        // won't have these keys at all. decodeIfPresent + defaults (rather than
        // synthesized Decodable, which would treat a non-Optional array as
        // required and throw) keeps decoding old-format payloads working.
        // shardMetadataAttempted defaults to false for the same reason — a sender
        // old enough not to know about it never attempted anything.
        enum CodingKeys: String, CodingKey {
            case sessionKey, prekeyBatch, shardOperations, custodyManifest, custodyManifestCount, expectedShards, expectedShardsCount, shardMetadataAttempted, senderEphemeralSignature
        }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            self.sessionKey               = try c.decode(Data.self, forKey: .sessionKey)
            self.prekeyBatch              = try c.decodeIfPresent(SealedPayload.PrekeySyncBatch.self, forKey: .prekeyBatch)
            self.shardOperations          = try c.decodeIfPresent([ShardOperation].self, forKey: .shardOperations) ?? []
            self.custodyManifest          = try c.decodeIfPresent([UUID].self, forKey: .custodyManifest) ?? []
            self.custodyManifestCount     = try c.decodeIfPresent(Int.self, forKey: .custodyManifestCount) ?? 0
            self.expectedShards           = try c.decodeIfPresent([UUID].self, forKey: .expectedShards) ?? []
            self.expectedShardsCount      = try c.decodeIfPresent(Int.self, forKey: .expectedShardsCount) ?? 0
            self.shardMetadataAttempted   = try c.decodeIfPresent(Bool.self, forKey: .shardMetadataAttempted) ?? false
            self.senderEphemeralSignature = try c.decodeIfPresent(Data.self, forKey: .senderEphemeralSignature)
        }
    }

    // MARK: - Fields

    /// Protocol version. Included in AAD — tampering causes `open` to throw.
    let version: Version

    /// Minimal key-exchange fields. Authenticated as AAD — not encrypted.
    /// An observer can read `mode`, `ephemeralPublicKey`, and `prekeyID` only.
    /// For group bundles: `mode = .group`, `ephemeralPublicKey = Data()`, `prekeyID = nil`.
    let secrecy: SecrecyContext

    /// AES-GCM combined payload: nonce(12B) || JSON(SealedPayload) || tag(16B).
    /// For group bundles the session key is in each `Recipient.wrappedPayload`;
    /// `SealedPayload.prekeyBatch` is always nil (replenishment is per-recipient).
    let ciphertext: Data

    /// 16 random bytes, unique per bundle. Pre-decryption routing — not in AAD.
    let fingerprintNonce: Data

    /// SHA-256(senderLongTermPublicKey || fingerprintNonce). Routing — not in AAD.
    let senderFingerprint: Data

    /// Group envelope — non-nil iff `secrecy.mode == .group`.
    let group: GroupEnvelope?

    init(
        version: Version,
        secrecy: SecrecyContext,
        ciphertext: Data,
        fingerprintNonce: Data,
        senderFingerprint: Data,
        group: GroupEnvelope? = nil
    ) {
        self.version           = version
        self.secrecy           = secrecy
        self.ciphertext        = ciphertext
        self.fingerprintNonce  = fingerprintNonce
        self.senderFingerprint = senderFingerprint
        self.group             = group
    }

    // MARK: - Serialisation

    func encoded(version: Version = .v3fs) throws -> Data {
        switch version {
        case .v4, .groupCapable, .groupShardCapable:
            return try WireHandle.encode(self)
        default:
            return try JSONEncoder().encode(self)
        }
    }

    static func decoded(from data: Data) throws -> OccultaBundle {
        if data.prefix(WireHandle.magic.count).elementsEqual(WireHandle.magic) {
            let parsed = try WireHandle.parse(data)
            return try OccultaBundle(wireBundle: parsed)
        }
        return try JSONDecoder().decode(OccultaBundle.self, from: data)
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

    var isForwardSecret: Bool {
        self.secrecy.mode == .forwardSecret || self.secrecy.mode == .forwardSecretNoPQ
    }

    var securityLabel: String {
        switch secrecy.mode {
        case .forwardSecret:     return "Forward Secret"
        case .forwardSecretNoPQ: return "Forward Secret"
        case .longTermFallback:  return "Standard Encryption"
        case .longTermNoPQ:      return "Standard Encryption"
        case .group:             return "Group Encrypted"
        case .unsupported:       return "Unsupported"
        }
    }
}

// MARK: - ShardPadding

/// Fixed-size tiering for `RecipientPayload`'s shard-related arrays.
///
/// A group recipient's ciphertext length must not reveal whether they carry real
/// shard content, since `GroupEnvelope`/`Recipient.wrappedPayload` travel as a
/// cleartext JSON TLV block (see `WireHandle.encode(_:)`) — anyone holding the
/// bundle can measure per-recipient byte lengths without decrypting anything.
/// `ContactManager.encryptGroupBundle` pads every recipient's shard arrays up to
/// the same tier for a given send, computed from the real maximum across all
/// recipients in that send.
enum ShardPadding {
    /// Smallest doubling tier (2, 4, 8, 16, ...) that fits `count`. No upper bound —
    /// tiers grow to fit whatever the real maximum is for this specific send, so
    /// there is no reject/truncate path. Tradeoff: bundle size correlates with real
    /// content amount at tier granularity (coarser than exact size, far coarser than
    /// per-recipient distinguishability) across bundles observed over time — an
    /// accepted residual, not the leak this scheme closes.
    static func tier(for count: Int) -> Int {
        var t = 2
        while t < count { t *= 2 }
        return t
    }
}

// MARK: - WireHandle bridge

extension OccultaBundle {
    /// Reconstruct an `OccultaBundle` from a parsed binary outer envelope.
    init(wireBundle b: WireHandle.Bundle) throws {
        guard let version = WireHandle.byteToVersion(b.version) else {
            throw BundleError.unsupportedVersion
        }
        guard let mode = WireHandle.byteToMode(b.mode) else {
            throw BundleError.unsupportedMode
        }
        let prekeyID: String?
        if let pid = b.prekeyID {
            guard let s = String(data: pid, encoding: .utf8) else {
                throw BundleError.unsupportedVersion
            }
            prekeyID = s
        } else {
            prekeyID = nil
        }
        self.version           = version
        self.secrecy           = SecrecyContext(mode: mode, ephemeralPublicKey: b.ephemeralKey, prekeyID: prekeyID)
        self.ciphertext        = b.ciphertext
        self.fingerprintNonce  = b.fingerprintNonce
        self.senderFingerprint = b.senderFingerprint
        self.group             = try b.groupEnvelope.map { try JSONDecoder().decode(GroupEnvelope.self, from: $0) }
    }
}

//
//  Vault+Model.swift
//  Occulta
//
//  SwiftData models for the Occulta Vault (Issue #34).
//
//  Design decisions:
//  - VaultEntryType uses UInt8 raw values so "entryType rawValue byte" in the
//    AAD construction is a literal single byte, not a String encoding.
//  - All VaultEntry properties carry defaults — lightweight SwiftData migration
//    requires non-required new columns (CODE_GENERATION_GUIDELINES §SwiftData).
//  - entryType is stored as Int (SwiftData-native scalar); the UInt8 round-trip
//    is lossless for the five defined cases.
//  - ShardDistributionMetadata is Codable and encrypted as a blob; it is never
//    stored in a relationship to avoid leaking shard-count metadata.
//

import Foundation
import SwiftData
import CryptoKit
import OccultaFormats

// MARK: - Vault

/// Singleton row — exactly one `Vault` instance ever exists. Holds device-wide vault state that
/// doesn't belong to any one entry: today, the parent side of the `PendingShamirSecretRestore`
/// relationship below.
///
/// ⚠️ No longer the "one seal covers everything" shape `RECOVERY_BUFFER_LAYERING.md` §6 item 9.2
/// described — that relied on a single sealed blob so any change reseals the whole thing, closing
/// `bugs.md` Bug 120 as a side effect. Moving to a real SwiftData relationship (independently-sealed
/// child rows) walks back that property; a write to one `PendingShamirSecretRestore` row no longer
/// touches any other. Already reconciled with the doc, not an open gap — §9.3 (2026-09-13) discusses
/// this exact consequence directly and accepts it, distinguishing it from Bug 120's actual claim (row
/// count alone still reveals nothing; which row's bytes change over time now does).
///
/// Singleton discipline (fetch-or-create, exactly one row): `VaultManager.ensureVaultExists()`/
/// `.requireVault()` (`Vault+Manager+PendingRestore.swift`), mirroring `Manager.Security.requireConfig()`.
@Model
final class Vault {

    // MARK: Persisted fields

    /// Random identifier. Bound into AAD; mutating invalidates decryption.
    var id: UUID = UUID()

    @Relationship(deleteRule: .cascade, inverse: \PendingShamirSecretRestore.vault)
    var pendingRestores: [PendingShamirSecretRestore] = []

    // MARK: Init

    init(id: UUID = UUID()) {
        self.id = id
    }

    // MARK: AAD

    /// Authenticated additional data — kept for consistency with every other model's `aad()`, even
    /// though `Vault` no longer has an `encryptedPayload` field of its own to bind it to.
    ///
    ///   id.uuidString (UTF-8)   — 36 bytes
    func aad() -> Data {
        self.id.uuidString.data(using: .utf8)!
    }
}

// MARK: - PendingShamirSecretRestore

/// One backup key currently being restored from Shamir shares. Keyed by the secret's own identity
/// (its `distributionID`), not by depth, which the earlier per-depth-array design (§6 item 9.2 as
/// originally written) could not do. Per-entry PEK restores used this too until per-entry splitting
/// was retired (`decisions.md`, "Retire per-entry splitting").
///
/// Privacy model — encryption at rest:
/// - `id` (plaintext) — random, bound into AAD-like use elsewhere in the codebase; not itself bound
///   to anything here since `attributeID`/`deletionToken` are sealed independently (see below).
/// - `attributeID`, `deletionToken` — sealed under the **local key**
///   (`Manager.Ambient.keyManager.createHybridLocalEncryptionKey()`), not the restore vault key — the same forced
///   split `BackupEncryptionKey.depth`/`.deletionToken` already uses: whatever eventually orphans
///   these rows runs from `Manager.Security`, which never derives the restore vault key, only the
///   ambient local key.
/// - `shards` — sealed, padded `[PendingRestoreShardSlot]` (exactly 255 elements, fixed-width encoded
///   then AES-GCM sealed as one blob), under the restore vault key
///   (`KeyManagerProtocol.deriveRestoreVaultKey()`) — the same key domain the shard content itself
///   needs, distinct from `attributeID`/`deletionToken`'s local-key domain above. The fixed-width
///   codec itself (byte layout) is not yet written — this field's shape is settled, its encoding isn't.
///
/// Lifecycle: `deletionToken` flips from live to orphaned once the secret this row tracks has been
/// consumed (successfully reconstructed) — never deleted, matching `VaultEntry`/`BackupEncryptionKey`'s
/// own orphan-in-place convention exactly.
///
/// Open, not decided here: whether this needs the same eager-filler-baseline treatment
/// `BackupEncryptionKey` got, so total row count (live + orphaned) doesn't reveal how many restores
/// have ever happened — or whether, like `Contact.Profile`'s declined fix (Bug 112), this population
/// is rare enough not to need it.
@Model
final class PendingShamirSecretRestore {

    // MARK: Persisted fields

    var id: UUID = UUID()

    /// Encrypted — the secret's own identity: a backup key's `distributionID`. Never a plaintext
    /// column — see the class doc.
    var attributeID: Data? = nil

    /// Encrypted — live/orphaned sentinel, same convention as `VaultEntry`/`BackupEncryptionKey`.
    var deletionToken: Data? = nil

    /// Sealed, padded `[PendingRestoreShardSlot]` — exactly 255 elements once decoded, the Shamir
    /// ceiling, so no genuine distribution can ever be truncated by it. `nil` only before this row's
    /// shard slots are ever written. Key = `KeyManagerProtocol.deriveRestoreVaultKey()`; see the class
    /// doc for why this differs from `attributeID`/`deletionToken`'s key domain.
    var shards: Data? = nil

    /// Inverse side of `Vault.pendingRestores`.
    var vault: Vault?

    // MARK: AAD

    /// Authenticated additional data for AES-GCM seal/open of `shards` — the one field on this
    /// model sealed via a direct `AES.GCM.seal(..., authenticating:)` call rather than the generic
    /// `Data.encrypt(using:)` helper. `attributeID`/`deletionToken` use that generic helper's own
    /// fixed AAD instead, the same split `BackupEncryptionKey.depth`/`.deletionToken` already use —
    /// see `bugs.md` Bug 123 for why that's a known, accepted gap for the small fields, not this one.
    ///
    ///   id.uuidString (UTF-8)   — 36 bytes
    ///
    /// ⚠️ Sealed contract. Any change makes existing ciphertext unreadable.
    func aad() -> Data {
        self.id.uuidString.data(using: .utf8)!
    }

    // MARK: Orphaning

    static let liveToken:     Data = Data([0])
    static let orphanedToken: Data = Data([1])

    /// Fail-safe: undecryptable, nil, or ambiguous reads as orphaned — same convention as
    /// `BackupEncryptionKey.isOrphaned(usingKey:)`.
    func isOrphaned(usingKey key: SymmetricKey) -> Bool {
        guard let data = self.deletionToken, let plain = data.decrypt(using: key) else { return true }
        return plain != Self.liveToken
    }

    // MARK: Init

    init(
        id:            UUID = UUID(),
        attributeID:   Data? = nil,
        deletionToken: Data? = nil,
        shards:        Data? = nil,
        vault:         Vault? = nil
    ) {
        self.id             = id
        self.attributeID    = attributeID
        self.deletionToken  = deletionToken
        self.shards         = shards
        self.vault          = vault
    }
}

/// One collected shard, or an empty slot — one element of `PendingShamirSecretRestore.shards`.
///
/// No longer carries an attestation field — removed 2026-09-14, `bugs.md` Bug 124. Branch B
/// (Bug 94 remedy 2) never verified the underlying share was genuine, only that a currently-
/// recognized identity vouched for it; once a trustee-set mutation regenerates the distribution
/// id/value (Bug 124's remedy), a stale credential can't reach this slot at all, and the vouching
/// step has nothing left to add over a direct current-trustee check.
struct PendingRestoreShardSlot: Codable {
    var signedAttribute: SignedAttribute? = nil
    /// Who sent it: a tag of the sender's `Contact.Profile.identifier` (`bugs.md` Bug 147).
    var sender:          TrusteeTag?      = nil
}

// MARK: - PendingShamirSecretRestore.ShardsCodec

extension PendingShamirSecretRestore {

    /// Fixed-width codec for `shards` — encodes/decodes exactly `shardCapacity`
    /// `PendingRestoreShardSlot`s to/from one padded blob, matching
    /// `VaultManager.Backup.PayloadCodec`'s own house style (version prefix, fixed
    /// slot count, random filler for anything absent). Sealed separately under the
    /// restore vault key — this type only handles the plaintext shape.
    ///
    /// Wire format (`payloadSize` bytes, always, whether 0 shards are in use or
    /// `shardCapacity`):
    /// ```
    /// byte 0–1    formatVersion         — UInt16 big-endian
    /// byte 2–...  shardCapacity × slot  — one PendingRestoreShardSlot each, in order
    /// ```
    ///
    /// Per-slot layout (`slotSize` = 449 bytes — no longer 862; the attestation half was removed
    /// 2026-09-14, `bugs.md` Bug 124, see `PendingRestoreShardSlot`'s own doc comment):
    /// ```
    /// byte 0        signedAttribute presence — 1 = real shard, 0 = filler
    /// byte 1–412    signedAttribute          — 412-byte SignedAttributeCodec;
    ///                                          random bytes when byte 0 is 0
    /// byte 413–448  sender                   — version 2: the 16-byte `TrusteeTag`,
    ///                                          then 20 random bytes; random bytes when
    ///                                          byte 0 is 0.
    /// ```
    ///
    /// Version 1 held the sender's identifier as a 36-byte UTF-8 string, assuming a UUID. Real
    /// identifiers are longer and were cut (`bugs.md` Bug 147); a version-1 slot decodes to the
    /// tag of that cut string, which matches no contact. Only builds of this branch wrote
    /// version 1, so only test devices hold it.
    enum ShardsCodec {

        static let formatVersion: UInt16 = 2
        static let shardCapacity: Int    = 255
        static let slotSize:      Int    = 1 + SignedAttributeCodec.size + 36
        static let payloadSize:   Int    = 2 + shardCapacity * slotSize

        enum CodecError: Error, Equatable {
            /// More slots than the Shamir ceiling could ever produce. Refuses to
            /// silently truncate real shard records — the one thing this codec
            /// must never do, matching `PayloadCodec.CodecError.tooManyShards`.
            case tooManySlots(count: Int)
        }

        /// Always writes `formatVersion` — dispatches on that constant the same way
        /// `decode(_:)` dispatches on whatever version tag it reads, matching
        /// `PayloadCodec.encode(_:)`'s own reasoning for why the two stay symmetric
        /// by construction.
        static func encode(_ slots: [PendingRestoreShardSlot]) throws -> Data {
            switch Self.formatVersion {
            case 2:  return try Self.encodeV2(slots)
            default: preconditionFailure("formatVersion \(Self.formatVersion) has no encoder")
            }
        }

        /// Dispatches on the version tag before checking length — see
        /// `PayloadCodec.decode(_:)`'s doc comment for why. `nil` for anything
        /// malformed: wrong length for its version, a version tag nothing below
        /// recognises, or (via `decodeV1`) a slot count exceeding `shardCapacity`.
        static func decode(_ data: Data) -> [PendingRestoreShardSlot]? {
            guard data.count >= 2 else { return nil }
            let version = UInt16(data[data.startIndex]) << 8 | UInt16(data[data.startIndex + 1])

            switch version {
            case 1, 2: return Self.decodeSlots(data, version: version)
            default:   return nil
            }
        }

        /// Versions 1 and 2 share one layout; only the sender field's meaning differs.
        private static func encodeV2(_ slots: [PendingRestoreShardSlot]) throws -> Data {
            guard slots.count <= Self.shardCapacity else {
                throw CodecError.tooManySlots(count: slots.count)
            }

            var out = Data(capacity: Self.payloadSize)
            var version = Self.formatVersion.bigEndian
            withUnsafeBytes(of: &version) { out.append(contentsOf: $0) }

            for slot in slots {
                out.append(try Self.encodeSlot(slot))
            }
            for _ in slots.count..<Self.shardCapacity {
                out.append(Self.emptySlot())
            }

            return out
        }

        private static func decodeSlots(_ data: Data, version: UInt16) -> [PendingRestoreShardSlot]? {
            guard data.count == Self.payloadSize else { return nil }
            let bytes = [UInt8](data)

            var slots: [PendingRestoreShardSlot] = []
            var offset = 2
            for _ in 0..<Self.shardCapacity {
                let slotBytes = Data(bytes[offset..<(offset + Self.slotSize)])
                if let slot = Self.decodeSlot(slotBytes, version: version) {
                    slots.append(slot)
                }
                offset += Self.slotSize
            }
            return slots
        }

        // MARK: Per-slot

        /// A slot with no signed attribute or no sender is treated as absent —
        /// filler, matching `PayloadCodec.decodeShard`'s own "no shard here" tag
        /// convention. `PendingRestoreShardSlot`'s two fields are only ever both
        /// present or both absent in practice (see its own doc comment), so
        /// requiring both here rather than either doesn't lose any real data.
        private static func encodeSlot(_ slot: PendingRestoreShardSlot) throws -> Data {
            guard let attribute = slot.signedAttribute, let sender = slot.sender else {
                return Self.emptySlot()
            }

            var out = Data(capacity: Self.slotSize)
            out.append(1)
            out.append(try SignedAttributeCodec.encode(attribute))
            out.append(sender.bytes)
            out.append(Data.randomBytes(36 - TrusteeTag.size))
            return out
        }

        /// `nil` for a genuinely-unused capacity slot (presence byte 0), a
        /// malformed one, or one whose `SignedAttributeCodec` region fails to
        /// decode — all three mean "no real shard here."
        private static func decodeSlot(_ data: Data, version: UInt16) -> PendingRestoreShardSlot? {
            let bytes = [UInt8](data)
            guard bytes[0] == 1 else { return nil }

            let attributeBytes = Data(bytes[1..<(1 + SignedAttributeCodec.size)])
            guard let attribute = SignedAttributeCodec.decode(attributeBytes) else { return nil }

            let senderStart = 1 + SignedAttributeCodec.size
            let sender: TrusteeTag?
            if version == 1 {
                sender = TrusteeTag(identifier: Self.string(fromFixedWidth: Array(bytes[senderStart..<Self.slotSize])))
            } else {
                sender = TrusteeTag(bytes: Data(bytes[senderStart..<(senderStart + TrusteeTag.size)]))
            }
            guard let sender else { return nil }

            return PendingRestoreShardSlot(signedAttribute: attribute, sender: sender)
        }

        private static func emptySlot() -> Data {
            var out = Data(capacity: Self.slotSize)
            out.append(0)
            out.append(Data.randomBytes(Self.slotSize - 1))
            return out
        }

        // MARK: Fixed-width string (version 1 only)
        //
        // Duplicated rather than shared with SignedAttributeCodec's own copy —
        // matching PayloadCodec's and ExportMetaSlotCodec's existing precedent of
        // each codec carrying its own private helpers rather than a shared one.

        /// Reads a version-1 sender field: the identifier's UTF-8, cut at 36 bytes and
        /// zero-padded. Trims at the first zero byte.
        private static func string(fromFixedWidth bytes: [UInt8]) -> String {
            let trimmed = bytes.prefix { $0 != 0 }
            return String(decoding: trimmed, as: UTF8.self)
        }
    }

    /// Fixed-width codec for one `SignedAttribute` — sized for exactly the one
    /// category `ShardsCodec` writes (`.shard`) and exactly one secret size (32
    /// bytes — true of both a BEK and a PEK today, the two secret kinds
    /// `PendingShamirSecretRestore.attributeID` currently names). `encode` guards
    /// `value.count == 33` and throws rather than silently truncating a future,
    /// differently-sized secret kind into unusable key material.
    ///
    /// Previously also covered `.attestation` — removed 2026-09-14 along with that
    /// field, see `PendingRestoreShardSlot`'s doc comment (`bugs.md` Bug 124).
    ///
    /// Layout (`size` = 412 bytes — corrected 2026-09-13, was 404: `signature` was
    /// sized assuming a raw r‖s signature, but `KeyManagerProtocol.signData(_:)`
    /// returns a genuinely DER-encoded one
    /// (`Key+Manager.swift`'s own doc comment says so directly), and this exact
    /// subsystem already had an established size for that at the time —
    /// `ShardCustody+Manager.swift`'s `attestationFiller` sized its filler signature
    /// at 72 bytes, not 64, specifically to match the real thing. That function no
    /// longer exists — `bugs.md` Bug 125, 2026-09-19, removed attestation entirely —
    /// but the 72-byte number it confirmed is still correct, DER-encoded ECDSA-P256
    /// signatures being 70-72 bytes regardless of what else changed):
    /// ```
    /// byte 0–15    id            — raw UUID bytes
    /// byte 16–271  label         — UTF-8, fixed-width, padded/truncated to 256
    /// byte 272–304 value         — GF(2^8) share: 32-byte value + 1-byte x-coordinate
    /// byte 305     category      — UInt8 tag, exhaustive over all 10 SignedAttribute.Category cases
    /// byte 306–377 signature     — DER-encoded ECDSA-P256, padded/truncated to 72
    ///                              (DER is self-delimiting — its own SEQUENCE length
    ///                              says how many of these 72 bytes are real, so no
    ///                              separate length field is needed)
    /// byte 378–385 createdAt     — UInt64 big-endian epoch seconds
    /// byte 386     expiresAt tag — 1 = present, 0 = absent
    /// byte 387–394 expiresAt     — UInt64 big-endian epoch seconds, zero-filled if absent
    /// byte 395     entryID tag   — 1 = present, 0 = absent
    /// byte 396–411 entryID       — raw UUID bytes, zero-filled if absent
    /// ```
    enum SignedAttributeCodec {

        static let size: Int = 16 + 256 + 33 + 1 + 72 + 8 + 1 + 8 + 1 + 16

        enum CodecError: Error, Equatable {
            /// `.shard` attributes carry exactly a 1-byte x-coordinate plus a
            /// 32-byte GF(2^8) share value — 33 bytes total
            /// (`ShamirSecretSharing.split`'s own output shape). A different size
            /// means this wasn't a real shard, or something upstream already
            /// corrupted it; silently truncating key material is the one thing
            /// this codec must never do.
            case unexpectedValueSize(count: Int)
            /// DER-encoded ECDSA-P256 signatures are 70-72 bytes in practice; 72
            /// is the fixed slot. Longer would be silently truncated into an
            /// unverifiable signature, so this throws instead.
            case signatureTooLong(count: Int)
        }

        static func encode(_ attribute: SignedAttribute) throws -> Data {
            guard attribute.value.count == 33 else {
                throw CodecError.unexpectedValueSize(count: attribute.value.count)
            }
            guard attribute.signature.count <= 72 else {
                throw CodecError.signatureTooLong(count: attribute.signature.count)
            }

            var out = Data(capacity: Self.size)
            out.append(Self.uuidBytes(attribute.id))                        // 16
            out.append(Self.fixedWidthUTF8(attribute.label, count: 256))    // 256
            out.append(attribute.value)                                    // 33
            out.append(Self.tag(for: attribute.category))                  // 1
            out.append(attribute.signature)
            out.append(Data(repeating: 0, count: 72 - attribute.signature.count)) // 72

            var created = UInt64(max(0, attribute.createdAt.timeIntervalSince1970)).bigEndian
            withUnsafeBytes(of: &created) { out.append(contentsOf: $0) }    // 8

            if let expiresAt = attribute.expiresAt {
                out.append(1)
                var expires = UInt64(max(0, expiresAt.timeIntervalSince1970)).bigEndian
                withUnsafeBytes(of: &expires) { out.append(contentsOf: $0) }
            } else {
                out.append(0)
                out.append(Data(repeating: 0, count: 8))
            }                                                               // 1 + 8

            if let entryID = attribute.entryID {
                out.append(1)
                out.append(Self.uuidBytes(entryID))
            } else {
                out.append(0)
                out.append(Data(repeating: 0, count: 16))
            }                                                               // 1 + 16

            return out
        }

        static func decode(_ data: Data) -> SignedAttribute? {
            guard data.count == Self.size else { return nil }
            let bytes = [UInt8](data)

            guard let id = Self.uuid(fromBytes: Array(bytes[0..<16])) else { return nil }
            let label = Self.string(fromFixedWidth: Array(bytes[16..<272]))
            let value = Data(bytes[272..<305])
            guard let category = Self.category(fromTag: bytes[305]) else { return nil }

            guard let sigLength = Self.derSignatureLength(Array(bytes[306..<378])) else { return nil }
            let signature = Data(bytes[306..<(306 + sigLength)])

            let createdSeconds = bytes[378..<386].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
            let createdAt = Date(timeIntervalSince1970: TimeInterval(createdSeconds))

            let hasExpiresAt = bytes[386] == 1
            let expiresSeconds = bytes[387..<395].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
            let expiresAt = hasExpiresAt ? Date(timeIntervalSince1970: TimeInterval(expiresSeconds)) : nil

            let hasEntryID = bytes[395] == 1
            var entryID: UUID? = nil
            if hasEntryID {
                guard let decoded = Self.uuid(fromBytes: Array(bytes[396..<412])) else { return nil }
                entryID = decoded
            }

            return SignedAttribute(
                id: id, label: label, value: value, category: category,
                signature: signature, createdAt: createdAt, expiresAt: expiresAt, entryID: entryID
            )
        }

        // MARK: Category tag

        /// Exhaustive `switch`, not a dictionary literal — a future
        /// `SignedAttribute.Category` case fails this at compile time instead of
        /// silently falling through, matching `PayloadCodec.tag(for:)`'s own
        /// convention for `ShardStatus`.
        private static func tag(for category: SignedAttribute.Category) -> UInt8 {
            switch category {
            case .financial:     return 1
            case .identity:      return 2
            case .medical:       return 3
            case .access:        return 4
            case .emergency:     return 5
            case .communication: return 6
            case .crypto:        return 7
            case .shard:         return 8
            case .attestation:   return 9
            case .other:         return 10
            }
        }

        private static func category(fromTag tag: UInt8) -> SignedAttribute.Category? {
            switch tag {
            case 1:  return .financial
            case 2:  return .identity
            case 3:  return .medical
            case 4:  return .access
            case 5:  return .emergency
            case 6:  return .communication
            case 7:  return .crypto
            case 8:  return .shard
            case 9:  return .attestation
            case 10: return .other
            default: return nil
            }
        }

        // MARK: Fixed-width string
        //
        // Duplicated rather than shared with ShardsCodec's own copy — see that
        // type's identical helpers for why.

        private static func fixedWidthUTF8(_ string: String, count: Int) -> Data {
            var bytes = Array(string.utf8.prefix(count))
            bytes.append(contentsOf: repeatElement(0, count: count - bytes.count))
            return Data(bytes)
        }

        private static func string(fromFixedWidth bytes: [UInt8]) -> String {
            let trimmed = bytes.prefix { $0 != 0 }
            return String(decoding: trimmed, as: UTF8.self)
        }

        // MARK: DER signature length

        /// DER SEQUENCE short-form length: `bytes[1]` is the content length
        /// directly, valid for anything under 128 bytes — true of every
        /// ECDSA-P256 signature this codec ever sees (68-70 bytes of content).
        /// This is what lets `signature` round-trip exactly, with no separate
        /// length field: the 72-byte slot may carry trailing zero padding after
        /// a shorter real signature, and this recovers exactly where it ends.
        private static func derSignatureLength(_ bytes: [UInt8]) -> Int? {
            guard bytes.count >= 2, bytes[0] == 0x30 else { return nil }
            let contentLength = Int(bytes[1])
            guard contentLength < 0x80 else { return nil }
            let total = 2 + contentLength
            guard total <= bytes.count else { return nil }
            return total
        }

        // MARK: UUID

        private static func uuidBytes(_ id: UUID) -> Data {
            withUnsafeBytes(of: id.uuid) { Data($0) }
        }

        private static func uuid(fromBytes bytes: [UInt8]) -> UUID? {
            guard bytes.count == 16 else { return nil }
            return UUID(uuid: (
                bytes[0], bytes[1], bytes[2],  bytes[3],  bytes[4],  bytes[5],  bytes[6],  bytes[7],
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
            ))
        }
    }
}

// MARK: - VaultEntryType

/// The kind of secret stored in a VaultEntry.
///
/// UInt8 raw values are stable wire identifiers for the AAD byte.
/// Never reorder or remove a case — doing so makes existing AADs unverifiable.
enum VaultEntryType: UInt8, Codable, CaseIterable {
    case seedPhrase = 0
    case note       = 1
    case keyToken   = 2
//    case document   = 3
//    case photo      = 4
}

// MARK: - ShardDistributionMetadata

/// Lifecycle state of a shard delivered to one contact.
///
/// Raw strings are stable wire identifiers — never rename or reorder.
enum ShardStatus: String, Codable {
    /// Shard bundle has been handed to the .occ pipeline, delivery unconfirmed.
    case pending
    /// Contact's app acknowledged receipt.
    case confirmed
    /// Revocation queued. Nothing on the trustee acts on it since implicit revoke
    /// (`expectedShards`) was removed (`bugs.md` Bug 141).
    case revokePending
    /// Owner has revoked this shard and the trustee confirmed deletion.
    case revoked
    /// Contact re-exchanged keys — their stored shard is cryptographically unreachable.
    case lost
}

extension ShardStatus {
    /// Returns `true` when transitioning from `current` to `next` is a legal
    /// state machine step.
    ///
    /// Valid transitions:
    ///   pending       → confirmed | lost
    ///   confirmed     → revokePending | lost
    ///   revokePending → revoked | confirmed  (confirmed = revoke cancelled)
    ///   revoked       → (terminal — no outgoing transitions)
    ///   lost          → (terminal — no outgoing transitions)
    ///
    /// Any other transition (e.g. revoked → confirmed, confirmed → pending) is
    /// rejected to prevent inbound traffic from un-revoking a shard or degrading
    /// a healthy one.
    static func isValidTransition(from current: ShardStatus, to next: ShardStatus) -> Bool {
        switch current {
        case .pending:       return next == .confirmed    || next == .lost
        case .confirmed:     return next == .revokePending || next == .lost
        case .revokePending: return next == .revoked      || next == .confirmed
        case .revoked:       return false
        case .lost:          return false
        }
    }
}

/// A fixed-width stand-in for a `Contact.Profile.identifier`: the first 16 bytes of SHA-256
/// over `domainLabel` followed by the identifier's UTF-8.
///
/// Stored identifiers are variable-length — encrypted base64 since SecurityReview 2026-07-24
/// finding #11, or the raw value when that encryption fell back — so the fixed-width codecs
/// (`Backup.PayloadCodec`'s trustee records, `PendingShamirSecretRestore.ShardsCodec`'s
/// senders) store this instead (`bugs.md` Bugs 145–147). Compared, never reversed; it
/// depends on the whole identifier, not on how its encryption lays out the leading bytes.
nonisolated
struct TrusteeTag: Hashable, Codable {
    /// Separates this hash from any other SHA-256 of the same identifier the app might take.
    static let domainLabel = "occulta-trustee-tag"
    static let size = 16

    let bytes: Data

    init(identifier: String) {
        var input = Data(Self.domainLabel.utf8)
        input.append(Data(identifier.utf8))
        self.bytes = Data(SHA256.hash(data: input).prefix(Self.size))
    }

    /// `nil` unless `bytes` is exactly `size` long.
    init?(bytes: Data) {
        guard bytes.count == Self.size else { return nil }
        self.bytes = Data(bytes)
    }
}

/// One shard's delivery record within a ShardDistributionMetadata.
struct ShardRecord: Codable {
    /// The trustee: a tag of their `Contact.Profile.identifier`, not the identifier itself,
    /// which is variable-length ciphertext (`TrusteeTag`, `bugs.md` Bug 145). Match a contact
    /// with `isHeld(by:)`.
    let trustee: TrusteeTag
    /// The SignedAttribute.id for this shard — used as `attributeID` in `.replace` ShardOperations
    /// to identify which old shard a new distribution supersedes.
    let attributeID: UUID
    var status: ShardStatus
    /// When the shard was first distributed (bundle handed to the .occ pipeline).
    var distributedAt: Date? = nil

    init(trustee: TrusteeTag, attributeID: UUID, status: ShardStatus, distributedAt: Date? = nil) {
        self.trustee       = trustee
        self.attributeID   = attributeID
        self.status        = status
        self.distributedAt = distributedAt
    }

    /// Whether the contact stored as `identifier` holds this piece.
    func isHeld(by identifier: String) -> Bool {
        self.trustee == TrusteeTag(identifier: identifier)
    }

    // JSON is only read for v1.10.3's backup-key payload (`migrateLegacyBackupRowIfNeeded`),
    // whose records carry `contactIdentifier`; they are tagged on the way in (`bugs.md` Bug 146).
    private enum CodingKeys: String, CodingKey {
        case trustee, contactIdentifier, attributeID, status, distributedAt
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        if let trustee = try c.decodeIfPresent(TrusteeTag.self, forKey: .trustee) {
            self.trustee = trustee
        } else {
            self.trustee = TrusteeTag(identifier: try c.decode(String.self, forKey: .contactIdentifier))
        }
        self.attributeID   = try c.decode(UUID.self, forKey: .attributeID)
        self.status        = try c.decode(ShardStatus.self, forKey: .status)
        self.distributedAt = try c.decodeIfPresent(Date.self, forKey: .distributedAt)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(self.trustee, forKey: .trustee)
        try c.encode(self.attributeID, forKey: .attributeID)
        try c.encode(self.status, forKey: .status)
        try c.encodeIfPresent(self.distributedAt, forKey: .distributedAt)
    }
}

/// Tracks a Shamir split for one VaultEntry.
///
/// Stored in the backup key's payload (`BackupEncryptionKey.Payload`, fixed-width codec),
/// sealed with the vault key. Never persisted in clear.
struct ShardDistributionMetadata: Codable {
    /// Minimum shards required to reconstruct (k).
    let threshold: Int
    /// One record per trustee, in shard-index order (index 0 → shard with x=1, etc.).
    var shards: [ShardRecord]
}

// MARK: - VaultField

/// Identifies which ciphertext field an AAD blob belongs to.
///
/// Each `VaultEntry` ciphertext field gets a distinct byte in its AAD, making
/// cross-field ciphertext swaps fail GCM authentication. Raw values are stable
/// wire identifiers — never reorder or remove a case.
enum VaultField: UInt8 {
    case label             = 0x01
    case content           = 0x02
    case entryKey          = 0x03
    /// `shardDistributionEncrypted`, retired with per-entry splitting (`decisions.md`,
    /// "Retire per-entry splitting"). Kept so 0x04 is never reused.
    case shardDistribution = 0x04
}

// MARK: - SealedLabelPayload

/// Plaintext carried inside `VaultEntry.encryptedLabel`.
///
/// Bundling `type` here moves entry category out of plaintext storage and into
/// the AES-GCM–protected payload, eliminating the metadata leak while keeping
/// the label and type decryption in a single GCM open.
struct SealedLabelPayload: Codable {
    let type:  VaultEntryType
    let label: String
}

// MARK: - VaultEntry

@Model
final class VaultEntry {

    // MARK: Persisted fields

    var id: UUID        = UUID()
    var createdAt: Date = Date()

    /// AES-256-GCM ciphertext of `SealedLabelPayload` (type + label).
    ///
    /// Wire format: nonce(12B) ∥ ciphertext ∥ tag(16B). Sealed with the PEK;
    /// AAD = `entry.aad(for: .label)`.
    var encryptedLabel: Data   = Data()

    /// AES-256-GCM ciphertext of the entry content (nonce ∥ ciphertext ∥ tag).
    var encryptedContent: Data = Data()

    /// AES-256-GCM ciphertext of the per-entry key (PEK, 32 random bytes).
    ///
    /// Wire format: nonce(12B) ∥ ciphertext(32B) ∥ tag(16B) = 60 bytes total.
    /// Sealed with the vault key; AAD = `entry.aad(for: .entryKey)`.
    var encryptedEntryKey: Data = Data()

    /// Retired with per-entry splitting (`decisions.md`, "Retire per-entry splitting"):
    /// never written, cleared on every row by `VaultManager.retireEntrySplittingIfNeeded`.
    /// Leaves the schema next release, once every device has run that clean-up.
    var shardDistributionEncrypted: Data? = nil

    /// Encrypted `Int` depth stamp — the depth this entry was created at.
    /// nil = never classified (a legacy entry pre-dating this field); what that
    ///       resolves to is caller-specific — see `isVisible(atDepth:whenUnclassified:)`.
    /// N   = visible only at exactly depth N (an exact match, not a ceiling —
    ///       see `Manager.Security.visibleVaultEntries(from:)` and
    ///       `Docs/Bugs/v1.10.0/Vault-Entries-Created-At-A-Duress-Depth-Leak-Into-The-Real-Vault.md`
    ///       for why "visible 0...N" would let an entry created at a duress depth
    ///       leak into every shallower depth, including the real depth 0).
    /// Set once at creation (`VaultManager.addEntry`); never edited afterward.
    var visibleThroughDepth: Data? = nil

    /// Whether this entry has been orphaned — decommissioned in place rather than
    /// hard-deleted. Encrypted, and — deliberately unlike `Contact.Profile.deletionToken`
    /// — **always populated**, never nil in practice: nil/non-nil status is itself a
    /// free, zero-decryption signal (SQLite tracks column nullability structurally,
    /// independent of any encryption applied to the value), so a naive `SELECT COUNT(*)
    /// WHERE deletionToken IS NOT NULL` would still answer "how many are orphaned"
    /// without needing the key. Content is one of two fixed-width sentinels
    /// (`liveToken`/`orphanedToken` below) that encrypt to the same ciphertext length —
    /// the same "no plaintext boolean flags" principle `AppLayerConfig.pinEnabledPerDepth`
    /// already uses (Bug 51). Query via `isOrphaned(usingKey:)`, never `== nil`.
    ///
    /// Orphaned rows are never shown in any view and are excluded from every functional
    /// read via `VaultManager.fetchAllEntries()`, which is why marking this (rather than
    /// hard-deleting) still gives the row a stable, permanent physical presence — the
    /// same reasoning that motivated soft-deleting contacts instead of hard-deleting them
    /// (`bugs.md` Bug 13): a row count that drops in step with a duress-layer teardown is
    /// itself a forensic signal, and — combined with this field's own always-populated
    /// design — the *live* row count itself is no longer a free signal either.
    ///
    /// Written live at creation (`VaultManager.addEntry`, the backup-restore path) and
    /// flipped to orphaned by `Manager.Security`'s deactivation-time sweep when the depth
    /// this entry was stamped with (`visibleThroughDepth`) is freed by a deactivation and
    /// would otherwise be reused by a later, unrelated duress session (Bug 110,
    /// `bugs.md`) — `visibleThroughDepth` itself is left untouched (still names the depth
    /// this entry was created at, for the historical record) since exclusion from every
    /// read makes its value moot going forward.
    ///
    /// Cap: 50 orphaned rows; when full, the oldest is hard-deleted before a new one is
    /// written — same cap `Contact.Profile.deletionToken` uses.
    ///
    /// Sealed under the ambient local-DB key (`Manager.Ambient`), the same key
    /// `visibleThroughDepth` uses — deliberately not the vault's biometric-gated key:
    /// `Manager.Security.orphanVaultEntries` must be able to write this on deactivation
    /// without the vault ever being unlocked.
    var deletionToken: Data? = nil

    // MARK: Orphaning (Bug 110)

    /// Fixed-width sentinel plaintexts for `deletionToken`. Both are one byte and encrypt
    /// to the same ciphertext length — nothing about the sealed bytes reveals which one
    /// is inside without the key.
    static let liveToken:     Data = Data([0])
    static let orphanedToken: Data = Data([1])

    /// Whether this entry has been orphaned. Fail-safe: a `deletionToken` that is nil,
    /// undecryptable, or decrypts to neither known sentinel is treated as orphaned — the
    /// same "ambiguous means hidden" convention `isVisible` already uses elsewhere on
    /// this model. Nil means the row predates this field: every entry created by v1.10.3 or
    /// earlier. `DatabaseMigration.migrateVaultEntryDeletionTokens` gives those a live token
    /// at launch (`bugs.md` Bug 133); before it existed, upgrading hid all of them.
    func isOrphaned(usingKey key: SymmetricKey) -> Bool {
        guard let data = self.deletionToken, let plain = data.decrypt(using: key)
        else { return true }
        return plain != Self.liveToken
    }

    // MARK: Init

    init(encryptedLabel: Data, encryptedContent: Data) {
        self.id               = UUID()
        self.createdAt        = Date()
        self.encryptedLabel   = encryptedLabel
        self.encryptedContent = encryptedContent
    }

    // MARK: AAD construction

    /// Authenticated additional data for AES-GCM seal/open of a specific field.
    ///
    /// Wire encoding (concatenated, no length prefixes):
    ///
    ///   id.uuidString (UTF-8)                              — 36 bytes
    ///   ∥ field.rawValue (UInt8)                           —  1 byte
    ///   ∥ UInt64(createdAt.timeIntervalSince1970).bigEndian —  8 bytes
    ///
    /// Total: 45 bytes.
    ///
    /// The field discriminator prevents cross-field ciphertext swaps — sealing
    /// `encryptedContent` with `.label`'s AAD (or vice versa) fails authentication.
    ///
    /// ⚠️ This layout is a sealed contract. Any change to field order, encoding,
    /// or byte width makes all existing ciphertext permanently unreadable.
    func aad(for field: VaultField) -> Data {
        var data = Data()
        data.append(self.id.uuidString.data(using: .utf8)!)    // 36 bytes
        data.append(field.rawValue)                             //  1 byte

        var ts = UInt64(self.createdAt.timeIntervalSince1970).bigEndian
        data.append(Data(bytes: &ts, count: 8))                 //  8 bytes

        return data                                             // 45 bytes total
    }

    // MARK: Visibility

    /// Whether this entry is visible at `depth`, decoding `visibleThroughDepth` per
    /// its documented semantics: a non-nil but undecryptable ceiling (sensitive
    /// shell) is always hidden; a decodable ceiling is visible only at the exact
    /// depth it's stamped with; nil (never classified) resolves to `whenUnclassified`.
    ///
    /// Single source of truth for the decrypt/decode/compare logic — the part
    /// `Bug 27` was about, and the part that must not fork.
    ///
    /// Both current callers — `Manager.Security.visibleVaultEntries(from:)` (display,
    /// Bug 113) and `VaultManager.entriesVisible(atDepth:)` (backup export, staleness
    /// counts, Bug 114) — pass `whenUnclassified: depth == 0`: true only at the real
    /// depth. A nil entry is a real, persistent state, not something ever swept away —
    /// confirmed by grep, no code anywhere stamps an existing nil entry to a concrete
    /// depth, and `PQmigration.migrateDepthFieldsToFixedWidth`'s own doc comment calls
    /// it "a legitimate steady state." It must stay visible at the real depth 0,
    /// matching ordinary pre-feature usage, and stay hidden at every duress depth —
    /// including in a backup exported from one, where it would otherwise be real
    /// content leaking out under that depth's own backup key. `whenUnclassified` stays
    /// an explicit per-call parameter rather than a hardcoded default because the two
    /// callers arrived at the same answer for the same reason, not because they're
    /// guaranteed to always agree — a future caller with a genuinely different
    /// depth-0-only-or-not shape shouldn't have to fight a baked-in constant.
    func isVisible(atDepth depth: Int, whenUnclassified: Bool) -> Bool {
        guard let data = self.visibleThroughDepth else { return whenUnclassified }
        guard let plain = data.decrypt(), let value = DepthCodec.decode(plain)
        else { return false }
        return value == depth
    }

    /// Same as `isVisible(atDepth:whenUnclassified:)` but decrypts with an
    /// already-derived key instead of deriving one fresh per call. For batch
    /// callers (e.g. `VaultManager.entriesVisible(atDepth:)`) that would
    /// otherwise pay a Secure Enclave round trip per entry for what is always
    /// the same key — mirrors `Contact.Profile.isVisible(atDepth:usingKey:)`.
    func isVisible(atDepth depth: Int, whenUnclassified: Bool, usingKey key: SymmetricKey) -> Bool {
        guard let data = self.visibleThroughDepth else { return whenUnclassified }
        guard let plain = data.decrypt(using: key), let value = DepthCodec.decode(plain)
        else { return false }
        return value == depth
    }
}

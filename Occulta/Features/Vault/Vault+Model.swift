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

/// One secret currently being restored from Shamir shares — BEK or otherwise (a per-entry PEK's own
/// `VaultEntry.id` works identically). Keyed by the secret's own identity, not by depth, so this
/// generalizes past BEK-restore, which the earlier per-depth-array design (§6 item 9.2 as originally
/// written) could not.
///
/// Privacy model — encryption at rest:
/// - `id` (plaintext) — random, bound into AAD-like use elsewhere in the codebase; not itself bound
///   to anything here since `attributeID`/`deletionToken` are sealed independently (see below).
/// - `attributeID`, `deletionToken` — sealed under the **local key**
///   (`Manager.Key().createHybridLocalEncryptionKey()`), not the restore vault key — the same forced
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

    /// Encrypted — the secret's own identity: a BEK `distributionID`, a `VaultEntry.id` for a
    /// per-entry PEK restore, or any future secret kind. Never a plaintext column — see the class doc.
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
    var signedAttribute:  SignedAttribute? = nil
    var senderIdentifier: String?          = nil
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
    /// byte 413–448  senderIdentifier         — 36-byte UTF-8 UUID string;
    ///                                          random bytes when byte 0 is 0.
    ///                                          Unlike `PayloadCodec.ShardRecord.
    ///                                          contactIdentifier` (the closest
    ///                                          precedent, encoded as 16 raw UUID
    ///                                          bytes), this stays the 36-byte
    ///                                          string form already sized in
    ///                                          `RECOVERY_BUFFER_LAYERING.md` §6
    ///                                          item 9.3 — open whether to tighten
    ///                                          this to 16 bytes later.
    /// ```
    enum ShardsCodec {

        static let formatVersion: UInt16 = 1
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
            case 1:  return try Self.encodeV1(slots)
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
            case 1:  return Self.decodeV1(data)
            default: return nil
            }
        }

        private static func encodeV1(_ slots: [PendingRestoreShardSlot]) throws -> Data {
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

        private static func decodeV1(_ data: Data) -> [PendingRestoreShardSlot]? {
            guard data.count == Self.payloadSize else { return nil }
            let bytes = [UInt8](data)

            var slots: [PendingRestoreShardSlot] = []
            var offset = 2
            for _ in 0..<Self.shardCapacity {
                let slotBytes = Data(bytes[offset..<(offset + Self.slotSize)])
                if let slot = Self.decodeSlot(slotBytes) {
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
            guard let attribute = slot.signedAttribute, let senderIdentifier = slot.senderIdentifier else {
                return Self.emptySlot()
            }

            var out = Data(capacity: Self.slotSize)
            out.append(1)
            out.append(try SignedAttributeCodec.encode(attribute))
            out.append(Self.fixedWidthUTF8(senderIdentifier, count: 36))
            return out
        }

        /// `nil` for a genuinely-unused capacity slot (presence byte 0), a
        /// malformed one, or one whose `SignedAttributeCodec` region fails to
        /// decode — all three mean "no real shard here."
        private static func decodeSlot(_ data: Data) -> PendingRestoreShardSlot? {
            let bytes = [UInt8](data)
            guard bytes[0] == 1 else { return nil }

            let attributeBytes = Data(bytes[1..<(1 + SignedAttributeCodec.size)])
            guard let attribute = SignedAttributeCodec.decode(attributeBytes) else { return nil }

            let senderBytes = Array(bytes[(1 + SignedAttributeCodec.size)..<Self.slotSize])
            let senderIdentifier = Self.string(fromFixedWidth: senderBytes)

            return PendingRestoreShardSlot(signedAttribute: attribute, senderIdentifier: senderIdentifier)
        }

        private static func emptySlot() -> Data {
            var out = Data(capacity: Self.slotSize)
            out.append(0)
            out.append(Data.randomBytes(Self.slotSize - 1))
            return out
        }

        // MARK: Fixed-width string
        //
        // Duplicated rather than shared with SignedAttributeCodec's own copy —
        // matching PayloadCodec's and ExportMetaSlotCodec's existing precedent of
        // each codec carrying its own private helpers rather than a shared one.

        private static func fixedWidthUTF8(_ string: String, count: Int) -> Data {
            var bytes = Array(string.utf8.prefix(count))
            bytes.append(contentsOf: repeatElement(0, count: count - bytes.count))
            return Data(bytes)
        }

        /// Trims at the first zero byte — every real sender identifier is a UUID
        /// string (never contains one), so this only ever strips genuine padding.
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
    /// Revocation queued; trustee deletes it once a bundle omits it from
    /// `expectedShards` (`ShardCustodyManager.processExpectedShards`).
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

/// One shard's delivery record within a ShardDistributionMetadata.
struct ShardRecord: Codable {
    /// `Contact.Profile.identifier` — a stable SwiftData UUID, not derived from the key fingerprint.
    let contactIdentifier: String
    /// The SignedAttribute.id for this shard — used as `attributeID` in `.replace` ShardOperations
    /// to identify which old shard a new distribution supersedes.
    let attributeID: UUID
    var status: ShardStatus
    /// When the shard was first distributed (bundle handed to the .occ pipeline).
    var distributedAt: Date? = nil
}

/// Tracks a Shamir split for one VaultEntry.
///
/// Serialised with JSONEncoder, then AES-GCM sealed with the vault key and
/// stored in VaultEntry.shardDistributionEncrypted. Never persisted in clear.
struct ShardDistributionMetadata: Codable {
    /// Minimum shards required to reconstruct (k).
    let threshold: Int
    /// One record per trustee, in shard-index order (index 0 → shard with x=1, etc.).
    var shards: [ShardRecord]
}

// MARK: - RecoveryHealthSummary

/// Aggregate vault-wide recovery health, computed on unlock and after each
/// shard status mutation. `nil` when the vault is locked.
struct RecoveryHealthSummary {

    enum EntryStatus {
        /// Active shards are below threshold but at least one remains.
        case degraded
        /// No active shards remain — recovery is impossible without redistribution.
        case critical
    }

    struct AffectedEntry {
        let entryID:   UUID
        let label:     String
        let entryType: VaultEntryType
        let status:    EntryStatus
        let active:    Int
        let threshold: Int
    }

    /// Entries whose active shard count is below threshold.
    /// Sorted: critical first, then degraded, both groups alphabetical by label.
    /// Empty when all distributed entries meet their threshold.
    let affected: [AffectedEntry]

    var isEmpty: Bool { affected.isEmpty }
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

    /// Encrypted JSON-encoded ShardDistributionMetadata.
    /// nil until an SSS split has been performed for this entry.
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
    /// A side effect worth knowing, not something this field has to implement itself: an
    /// orphaned entry's `ShardRecord`s stop appearing in `VaultManager.
    /// shardRecordsForTrustee(_:)` (which reads through `fetchAllEntries()`), so the next
    /// bundle sent to a trustee holding one of this entry's shards omits it from
    /// `expectedShards` — the trustee deletes their own copy via `ShardCustodyManager.
    /// processExpectedShards`'s existing implicit-revoke handling. No new shard-status
    /// bookkeeping needed for that to happen.
    ///
    /// Cap: 50 orphaned rows; when full, the oldest is hard-deleted before a new one is
    /// written — same cap `Contact.Profile.deletionToken` uses.
    ///
    /// Sealed under the ambient local-DB key (`Manager.Key()`), the same key
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
    /// this model. In practice `deletionToken` is always populated and always decryptable
    /// under the current key; nil only occurs for a row that predates this field
    /// entirely, which cannot happen on this branch (added the same session it started
    /// being written), but the fallback costs nothing to keep.
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

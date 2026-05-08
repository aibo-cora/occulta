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
    /// Revocation queued; `.revoke` operation not yet confirmed by the trustee.
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
}

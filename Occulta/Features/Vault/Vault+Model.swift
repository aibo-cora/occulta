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

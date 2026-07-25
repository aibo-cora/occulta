//
//  Group+Model.swift
//  Occulta
//

import CryptoKit
import Foundation
import Security
import SwiftData

// MARK: - Group Model

@Model
final class Group {

    /// Encrypted UUID string — the local identifier for this group.
    /// Decrypted at send time to populate GroupEnvelope.id.
    /// Stored encrypted so a forensic examiner cannot correlate the DB record
    /// with a cleartext GroupEnvelope.id seen in an intercepted bundle.
    var encryptedID: Data?

    /// Encrypted display name. Readable at any depth — same local DB key shared
    /// across layers, consistent with how contact names behave.
    var encryptedName: Data?

    /// Depth-0 (real layer) member slots. Always exactly 32 entries.
    /// Real slots: AES-GCM(128-byte padded identifier) = 156 bytes (12 nonce + 128 data + 16 tag).
    /// Unused slots: 156 cryptographically random bytes, size-identical to real entries.
    private(set) var realMemberSlots: [Data]

    /// Depth-1 (first duress layer) member slots. Same invariants as realMemberSlots.
    /// Named for schema continuity with pre-1.9.1 rows, where this was the single shared
    /// bucket for every duress depth. As of 1.9.1 it backs depth 1 specifically; depths
    /// 2+ use `deeperMemberSlots`. See Bug 73.
    private(set) var duressMemberSlots: [Data]

    /// Member slots for duress depths 2 and beyond. `deeperMemberSlots[0]` = depth 2,
    /// `deeperMemberSlots[1]` = depth 3, ... up to depth `depthCount - 1`.
    ///
    /// Before 1.9.1, every duress depth beyond the first shared `duressMemberSlots` — a
    /// group's decoy membership was identical at every coercion depth, breaking the
    /// documented multi-layer promise that each depth shows a different decoy set
    /// (Bug 73). This field gives depths 2+ their own independent, indistinguishable
    /// slot arrays, matching the granularity Secure Mode already gives contacts via
    /// `visibleThroughDepth`.
    ///
    /// Absent (empty) on groups created before 1.9.1 until their first membership edit
    /// post-upgrade, at which point `setMembers` pads it to full size — the same
    /// lazy-padding pattern `AppLayerConfig.ensurePadded()` uses.
    private(set) var deeperMemberSlots: [[Data]] = []

    /// Encrypted second-precision TimeInterval. Milliseconds truncated to prevent
    /// correlation with other observable events at sub-second resolution.
    var encryptedCreatedAt: Data?

    /// Fixed capacity per layer, matching AppLayerConfig.maxVerifierCount.
    static let slotCount = 32

    /// Padded plaintext size for member identifiers.
    /// CNContact identifiers are variable-length (observed up to 88 bytes on device);
    /// padding to a fixed size makes all slots — real and filler — produce identical
    /// ciphertext lengths, preventing size-based slot identification.
    static let maxIdentifierBytes = 128

    /// AES-GCM(128-byte padded identifier) = 12 (nonce) + 128 (data) + 16 (tag) = 156 bytes.
    /// Filler slots are also 156 bytes — indistinguishable by size.
    static let slotSize = 156

    /// Total depths supported: depth 0 (real) plus depths 1...31 (duress). Matches
    /// `AppLayerConfig.maxVerifierCount`, the system-wide cap on total layers — group
    /// membership storage must cover exactly as many depths as the rest of Secure Mode
    /// can create, no more and no less. Coincidentally equal to `slotCount` (member
    /// slots per depth) but a distinct concept.
    static let depthCount = 32

    // MARK: - Init

    init(name: String) throws {
        self.realMemberSlots    = try Self.freshFillerArray()
        self.duressMemberSlots  = try Self.freshFillerArray()
        self.deeperMemberSlots  = try (0..<(Self.depthCount - 2)).map { _ in try Self.freshFillerArray() }

        guard
            let encID   = try Data(UUID().uuidString.utf8).encrypt(),
            let encName = try Data(name.utf8).encrypt()
        else {
            throw GroupError.encryptionFailed
        }
        self.encryptedID   = encID
        self.encryptedName = encName

        let ts = floor(Date().timeIntervalSince1970)
        guard let encTS = try JSONEncoder().encode(ts).encrypt() else {
            throw GroupError.encryptionFailed
        }
        self.encryptedCreatedAt = encTS
    }

    // MARK: - Name

    func readName() -> String? {
        guard let decrypted = self.encryptedName?.decrypt() else { return nil }
        return String(data: decrypted, encoding: .utf8)
    }

    func writeName(_ name: String) throws {
        guard let encrypted = try Data(name.utf8).encrypt() else {
            throw GroupError.encryptionFailed
        }
        self.encryptedName = encrypted
    }

    // MARK: - ID

    func readID() -> UUID? {
        guard let decrypted = self.encryptedID?.decrypt(),
              let str       = String(data: decrypted, encoding: .utf8)
        else { return nil }
        return UUID(uuidString: str)
    }

    // MARK: - Created At

    func readCreatedAt() -> Date? {
        guard let decrypted = self.encryptedCreatedAt?.decrypt(),
              let ts        = try? JSONDecoder().decode(TimeInterval.self, from: decrypted)
        else { return nil }
        
        return Date(timeIntervalSince1970: ts)
    }

    // MARK: - Members

    /// Returns the contact identifiers stored at `depth`. Depth 0 is the real layer;
    /// 1...31 are duress depths, each with its own independent membership.
    /// Slots that fail to decrypt (filler) are silently skipped.
    func members(atDepth depth: Int) -> [String] {
        guard let key = try? Self.requireKey() else { return [] }
        return self.members(atDepth: depth, usingKey: key)
    }

    /// Same as `members(atDepth:)` but decrypts with an already-derived key instead of
    /// deriving one per slot. Used by the batch re-encryption paths below, which must
    /// reuse one derivation across every depth of every group rather than re-deriving
    /// per slot — see `ContactManager.cleanUpGroupDuressMembership`.
    func members(atDepth depth: Int, usingKey key: SymmetricKey) -> [String] {
        self.slots(atDepth: depth).compactMap { slot -> String? in
            guard let decrypted = slot.decrypt(using: key) else { return nil }
            // Strip null-byte padding introduced by encryptedSlots(for:).
            let trimmed = decrypted.prefix(while: { $0 != 0 })
            guard !trimmed.isEmpty,
                  let str = String(data: trimmed, encoding: .utf8)
            else { return nil }
            return str
        }
    }

    /// Derives the hybrid local DB key once, throwing if SE/Keychain is unavailable.
    /// Used by the no-key convenience overloads below (single-edit paths) and by
    /// `setMembers`, which derives its own key once per call rather than per slot.
    private static func requireKey() throws -> SymmetricKey {
        guard let key = try Manager.Key().createHybridLocalEncryptionKey() else {
            throw GroupError.keyUnavailable
        }
        return key
    }

    func addMember(_ identifier: String, atDepth depth: Int) throws {
        var current = self.members(atDepth: depth)

        guard !current.contains(identifier) else { return }
        guard current.count < Self.slotCount else { throw GroupError.capacityExceeded }

        current.append(identifier)

        try self.setMembers(current, atDepth: depth)
    }

    func removeMember(_ identifier: String, atDepth depth: Int) throws {
        var current = self.members(atDepth: depth)

        current.removeAll { $0 == identifier }

        try self.setMembers(current, atDepth: depth)
    }

    /// Removes each identifier in `identifiers` from every duress depth's membership
    /// (1...depthCount-1), leaving the real layer (depth 0) — and every *other* member
    /// at every duress depth — untouched.
    ///
    /// A contact hidden by a real-layer reclassification may already be a stale,
    /// invisible member of this group's duress-depth array — added back when they were
    /// still visible there. This removes exactly that stale entry, and nothing else — a
    /// user may have put real effort into building distinct multi-layer decoy
    /// membership, and hiding one unrelated contact must not destroy someone else's
    /// carefully-prepared decoy set. (This replaces an earlier version of this method
    /// that cleared *all* duress-depth membership on any depth-0 hide, which had exactly
    /// that destructive side effect.)
    ///
    /// Every depth is still re-encrypted regardless of whether any of `identifiers` were
    /// actually present there, for the same reason as `purgeMember(_:)`: touching only
    /// the depths where a removal occurred would reveal which depths held which contact.
    /// Called only from `ContactManager` when a reclassification happens at depth 0 —
    /// the one depth guaranteed not to be under coercion, since duress PINs never route
    /// there.
    ///
    /// Always pair a call to this with `refreshCiphertext()` on every *other* group in
    /// the store (see `ContactManager`'s classification cleanup) — otherwise "which
    /// groups had their ciphertext touched" becomes a keyless signal for "did this
    /// classification happen at depth 0."
    func purgeMembersFromDuressDepths(_ identifiers: Set<String>) throws {
        try self.purgeMembersFromDuressDepths(identifiers, usingKey: try Self.requireKey())
    }

    /// Same as `purgeMembersFromDuressDepths(_:)` but reuses an already-derived key.
    func purgeMembersFromDuressDepths(_ identifiers: Set<String>, usingKey key: SymmetricKey) throws {
        try self.reencryptAllDepths(usingKey: key) { depth in
            depth == 0
                ? self.members(atDepth: 0, usingKey: key)
                : self.members(atDepth: depth, usingKey: key).filter { !identifiers.contains($0) }
        }
    }

    /// Re-encrypts every depth's slots with fresh nonces without changing any plaintext
    /// membership. Pure camouflage: called whenever a classification change does *not*
    /// call `purgeMembersFromDuressDepths(_:)`, so that a classification save produces
    /// the identical observable footprint — every group's ciphertext changes —
    /// regardless of whether real content was actually removed or which depth the save
    /// happened at.
    func refreshCiphertext() throws {
        try self.refreshCiphertext(usingKey: try Self.requireKey())
    }

    /// Same as `refreshCiphertext()` but reuses an already-derived key across every
    /// depth instead of deriving one per slot.
    func refreshCiphertext(usingKey key: SymmetricKey) throws {
        try self.reencryptAllDepths(usingKey: key) { self.members(atDepth: $0, usingKey: key) }
    }

    /// Removes `identifier` from every depth's membership (0...depthCount-1), including
    /// the real layer — unlike `purgeMembersFromDuressDepths(_:)`, a deleted contact is
    /// invalid everywhere, not just hidden going forward. Every depth is still
    /// re-encrypted regardless of whether the identifier was actually present there;
    /// touching only the depths where a removal occurred would reveal which depths held
    /// this contact. Safe to call at any depth: this only ever touches the one
    /// identifier being removed and leaves every other member untouched, so it can't
    /// destroy separately-prepared decoy content.
    func purgeMember(_ identifier: String) throws {
        try self.purgeMember(identifier, usingKey: try Self.requireKey())
    }

    /// Same as `purgeMember(_:)` but reuses an already-derived key.
    func purgeMember(_ identifier: String, usingKey key: SymmetricKey) throws {
        try self.reencryptAllDepths(usingKey: key) { depth in
            self.members(atDepth: depth, usingKey: key).filter { $0 != identifier }
        }
    }

    /// Shared engine behind `purgeMembersFromDuressDepths(_:)`, `refreshCiphertext()`,
    /// and `purgeMember(_:)`: re-encrypts every depth with fresh nonces, sourcing each
    /// depth's plaintext from `content`. A database diff always shows every depth's
    /// slots change, regardless of which of the three callers ran or what it changed.
    private func reencryptAllDepths(usingKey key: SymmetricKey, content: (Int) -> [String]) throws {
        try self.ensureDeeperSlotsPadded()

        self.realMemberSlots   = try Self.encryptedSlots(for: content(0), using: key)
        self.duressMemberSlots = try Self.encryptedSlots(for: content(1), using: key)
        self.deeperMemberSlots = try (2..<Self.depthCount).map { try Self.encryptedSlots(for: content($0), using: key) }
    }

    // MARK: - Filler helpers

    static func freshFillerArray() throws -> [Data] {
        try (0..<slotCount).map { _ in try Self.randomFiller() }
    }

    // MARK: - Private

    /// Returns the raw slot array backing `depth`, or an empty array for an
    /// out-of-range or not-yet-padded deeper depth.
    private func slots(atDepth depth: Int) -> [Data] {
        switch depth {
        case 0:  return self.realMemberSlots
        case 1:  return self.duressMemberSlots
        default:
            let index = depth - 2
            guard index >= 0, index < self.deeperMemberSlots.count else { return [] }
            return self.deeperMemberSlots[index]
        }
    }

    /// Full recompute across every depth: encrypt each depth's identifiers with fresh
    /// nonces, pad to 32 slots with fresh random filler, then shuffle. Any database diff
    /// shows every depth's slots changed — no slot position, depth, or modified entry is
    /// identifiable. Recomputing only the touched depth would let an examiner correlate
    /// a diff with the depth that was just edited, which is exactly what Bug 73 fixes.
    private func setMembers(_ identifiers: [String], atDepth depth: Int) throws {
        guard depth >= 0, depth < Self.depthCount else { throw GroupError.invalidDepth }
        try self.ensureDeeperSlotsPadded()

        // Derived once and reused across all 32 depths' reads and writes below, rather
        // than per slot — see `members(atDepth:usingKey:)`.
        let key = try Self.requireKey()

        var perDepth = (0..<Self.depthCount).map { self.members(atDepth: $0, usingKey: key) }
        perDepth[depth] = identifiers

        self.realMemberSlots   = try Self.encryptedSlots(for: perDepth[0], using: key)
        self.duressMemberSlots = try Self.encryptedSlots(for: perDepth[1], using: key)
        self.deeperMemberSlots = try perDepth[2...].map { try Self.encryptedSlots(for: $0, using: key) }
    }

    /// Pads `deeperMemberSlots` to full size (depths 2...depthCount-1) with fresh filler.
    /// No-op for groups created at or after 1.9.1, which are already fully padded at
    /// init. Groups created before 1.9.1 have an empty array here; this brings them up
    /// to size the first time any membership edit touches them, mirroring
    /// `AppLayerConfig.ensurePadded()`.
    ///
    /// Kept `private` and only ever called from `reencryptAllDepths` (never on its
    /// own) — padding `deeperMemberSlots` in isolation would itself be a new forensic
    /// tell: a diff showing only that array change, while `realMemberSlots`/
    /// `duressMemberSlots` stay identical, would reveal "this group was just backfilled
    /// by a migration, not edited by the user." Always going through
    /// `reencryptAllDepths` (via `refreshCiphertext()`, `purgeMembersFromDuressDepths(_:)`,
    /// or `setMembers`) keeps every depth's ciphertext changing together, so a padding-only
    /// touch is indistinguishable from a real edit.
    ///
    /// An eager, launch-time version of this (sweeping every stored group up front,
    /// rather than waiting for each group's own first edit) was tried and reverted —
    /// see `Docs/Features/Secure Mode/bugs.md`. It caused real device crashes/launch
    /// freezes from the sheer number of Keychain-backed crypto round trips needed to
    /// touch every depth of every group at once. Given how few users have groups at
    /// all yet, the residual forensic gap this lazy-only path leaves (a group nobody
    /// edits after upgrading keeps a distinguishable row shape until its first edit)
    /// was judged an acceptable trade for now.
    private func ensureDeeperSlotsPadded() throws {
        while self.deeperMemberSlots.count < Self.depthCount - 2 {
            self.deeperMemberSlots.append(try Self.freshFillerArray())
        }
    }

    private static func encryptedSlots(for identifiers: [String], using key: SymmetricKey) throws -> [Data] {
        var slots: [Data] = try identifiers.map { id in
            let raw = Data(id.utf8)
            guard raw.count <= Self.maxIdentifierBytes else { throw GroupError.identifierTooLong }
            // Pad to maxIdentifierBytes so all real slots produce the same ciphertext
            // length as filler. Null bytes are safe — identifiers never contain them.
            let padded = raw + Data(repeating: 0, count: Self.maxIdentifierBytes - raw.count)
            guard let encrypted = try padded.encrypt(using: key) else { throw GroupError.encryptionFailed }
            return encrypted
        }
        while slots.count < slotCount {
            slots.append(try randomFiller())
        }
        slots.shuffle()
        return slots
    }

    private static func randomFiller() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: slotSize)
        guard SecRandomCopyBytes(kSecRandomDefault, slotSize, &bytes) == errSecSuccess else {
            throw GroupError.entropyUnavailable
        }
        return Data(bytes)
    }
}

// MARK: - Errors

enum GroupError: Error {
    case capacityExceeded
    case encryptionFailed
    case identifierTooLong
    case entropyUnavailable
    /// `depth` passed to a member-storage method was outside 0..<Group.depthCount.
    case invalidDepth
    /// Upfront hybrid key derivation failed (SE/Keychain unavailable) before a batch
    /// re-encryption pass began. Must abort the whole pass rather than proceed with a
    /// missing key — silently skipping the mandatory ciphertext refresh would itself be
    /// a forensic tell (see `ContactManager.cleanUpGroupDuressMembership`).
    case keyUnavailable
}

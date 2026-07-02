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
        self.slots(atDepth: depth).compactMap { slot -> String? in
            guard let decrypted = slot.decrypt() else { return nil }
            // Strip null-byte padding introduced by encryptedSlots(for:).
            let trimmed = decrypted.prefix(while: { $0 != 0 })
            guard !trimmed.isEmpty,
                  let str = String(data: trimmed, encoding: .utf8)
            else { return nil }
            return str
        }
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

        var perDepth = (0..<Self.depthCount).map { self.members(atDepth: $0) }
        perDepth[depth] = identifiers

        self.realMemberSlots   = try Self.encryptedSlots(for: perDepth[0])
        self.duressMemberSlots = try Self.encryptedSlots(for: perDepth[1])
        self.deeperMemberSlots = try perDepth[2...].map { try Self.encryptedSlots(for: $0) }
    }

    /// Pads `deeperMemberSlots` to full size (depths 2...depthCount-1) with fresh filler.
    /// No-op for groups created at or after 1.9.1, which are already fully padded at
    /// init. Groups created before 1.9.1 have an empty array here; this brings them up
    /// to size the first time any membership edit touches them, mirroring
    /// `AppLayerConfig.ensurePadded()`.
    private func ensureDeeperSlotsPadded() throws {
        while self.deeperMemberSlots.count < Self.depthCount - 2 {
            self.deeperMemberSlots.append(try Self.freshFillerArray())
        }
    }

    private static func encryptedSlots(for identifiers: [String]) throws -> [Data] {
        var slots: [Data] = try identifiers.map { id in
            let raw = Data(id.utf8)
            guard raw.count <= Self.maxIdentifierBytes else { throw GroupError.identifierTooLong }
            // Pad to maxIdentifierBytes so all real slots produce the same ciphertext
            // length as filler. Null bytes are safe — identifiers never contain them.
            let padded = raw + Data(repeating: 0, count: Self.maxIdentifierBytes - raw.count)
            guard let encrypted = try padded.encrypt() else { throw GroupError.encryptionFailed }
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
}

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

    /// Real-layer member slots. Always exactly 32 entries.
    /// Real slots: AES-GCM(contactIdentifier UTF-8) = 64 bytes.
    /// Unused slots: 64 cryptographically random bytes, size-identical to real entries.
    var realMemberSlots: [Data]

    /// Duress-layer member slots. Same invariants as realMemberSlots.
    /// A coercer at depth > 0 sees only this array — no cross-array probe vector.
    var duressMemberSlots: [Data]

    /// Encrypted second-precision TimeInterval. Milliseconds truncated to prevent
    /// correlation with other observable events at sub-second resolution.
    var encryptedCreatedAt: Data?

    /// Fixed capacity per layer, matching AppLayerConfig.maxVerifierCount.
    static let slotCount = 32

    /// AES-GCM(36-byte UUID string) = 12 (nonce) + 36 (data) + 16 (tag) = 64 bytes.
    /// Filler slots are also 64 bytes — indistinguishable by size.
    static let slotSize = 64

    // MARK: - Init

    init(name: String) throws {
        self.realMemberSlots    = Self.freshFillerArray()
        self.duressMemberSlots  = Self.freshFillerArray()

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

    /// Returns the contact identifiers stored in the active layer.
    /// Slots that fail to decrypt (filler) are silently skipped.
    func members(in layer: RoutingDepth) -> [String] {
        let slots = layer == .normal ? self.realMemberSlots : self.duressMemberSlots
        return slots.compactMap { slot -> String? in
            guard let decrypted = slot.decrypt(),
                  let str       = String(data: decrypted, encoding: .utf8),
                  str.count == 36
            else { return nil }
            return str
        }
    }

    func addMember(_ identifier: String, in layer: RoutingDepth) throws {
        var current = self.members(in: layer)
        guard !current.contains(identifier) else { return }
        guard current.count < Self.slotCount else { throw GroupError.capacityExceeded }
        current.append(identifier)
        try self.setMembers(current, in: layer)
    }

    func removeMember(_ identifier: String, in layer: RoutingDepth) throws {
        var current = self.members(in: layer)
        current.removeAll { $0 == identifier }
        try self.setMembers(current, in: layer)
    }

    // MARK: - Filler helpers

    static func freshFillerArray() -> [Data] {
        (0..<slotCount).map { _ in Self.randomFiller() }
    }

    // MARK: - Private

    /// Full recompute: encrypt each real identifier with a fresh nonce, pad to 32 slots
    /// with fresh random filler, then shuffle. Any database diff shows all 64 entries
    /// changed — no slot position or modified entry is identifiable.
    private func setMembers(_ identifiers: [String], in layer: RoutingDepth) throws {
        // Both arrays are always recomputed together. A DB diff that shows only one
        // array changed would reveal which layer was written — defeating the point
        // of having two indistinguishable arrays.
        let realIdentifiers   = layer == .normal ? identifiers : self.members(in: .normal)
        let duressIdentifiers = layer == .duress ? identifiers : self.members(in: .duress)
        self.realMemberSlots   = try Self.encryptedSlots(for: realIdentifiers)
        self.duressMemberSlots = try Self.encryptedSlots(for: duressIdentifiers)
    }

    private static func encryptedSlots(for identifiers: [String]) throws -> [Data] {
        var slots: [Data] = try identifiers.map { id in
            guard let encrypted = try Data(id.utf8).encrypt() else {
                throw GroupError.encryptionFailed
            }
            return encrypted
        }
        while slots.count < slotCount {
            slots.append(randomFiller())
        }
        slots.shuffle()
        return slots
    }

    private static func randomFiller() -> Data {
        var data = Data(count: slotSize)
        _ = data.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, slotSize, $0.baseAddress!)
        }
        return data
    }
}

// MARK: - Errors

enum GroupError: Error {
    case capacityExceeded
    case encryptionFailed
}

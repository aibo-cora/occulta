//
//  AppLayerConfigRotationTests.swift
//  OccultaTests
//
//  Regression coverage for Bug 76: `AppLayerConfig` was never re-keyed during the Secure
//  Mode local-DB key rotation.
//
//  Activation re-encrypted contacts, vault depth stamps and drafts under the staged key,
//  then deleted the superseded key — but every field on this row stayed sealed under the
//  old one. Only the fields an activation happened to rewrite post-commit survived. The
//  rest degraded silently to their documented fallbacks: a lowered PIN gate re-armed
//  itself, the persisted depth reset to 0, and blob indices for every depth except the one
//  just written became unreadable, orphaning the blobs they pointed at.
//
//  Fully deterministic — every field is sealed with an explicit key, so no Secure Enclave
//  is involved.
//

import Testing
import Foundation
import CryptoKit
@testable import Occulta

// MARK: - Tests

@Suite("Bug 76 — AppLayerConfig survives key rotation")
struct AppLayerConfigRotationTests {

    @Test("Scalar fields survive a rotation")
    func scalarsSurvive() throws {
        let oldKey = SymmetricKey(size: .bits256)
        let newKey = SymmetricKey(size: .bits256)
        let config = AppLayerConfig()

        config.persistedDepth        = try JSONEncoder().encode(3).encrypt(using: oldKey)
        config.coercerBaseDepth      = try JSONEncoder().encode(2).encrypt(using: oldKey)
        config.lockoutCountEncrypted = try JSONEncoder().encode(4).encrypt(using: oldKey)
        config.lockoutAnchorUptimeEncrypted =
            try JSONEncoder().encode(TimeInterval(987.5)).encrypt(using: oldKey)

        try config.reencrypt(from: oldKey, to: newKey)

        #expect(try decodeInt(config.persistedDepth, using: newKey) == 3)
        #expect(try decodeInt(config.coercerBaseDepth, using: newKey) == 2)
        #expect(try decodeInt(config.lockoutCountEncrypted, using: newKey) == 4)

        let uptimePlain = try #require(config.lockoutAnchorUptimeEncrypted?.decrypt(using: newKey))
        #expect(try JSONDecoder().decode(TimeInterval.self, from: uptimePlain) == 987.5)

        // And genuinely moved off the old key.
        #expect(config.persistedDepth?.decrypt(using: oldKey) == nil)
    }

    /// The Bug 76 Defect 3 case. A gate lowered under coercion is stored as `0` at that
    /// depth; before this fix the rotation stranded it and `readPinEnabled` fell back to
    /// `true`, silently re-arming a gate the user had deliberately dropped.
    @Test("A lowered PIN gate survives a rotation")
    func loweredGateSurvives() throws {
        let oldKey = SymmetricKey(size: .bits256)
        let newKey = SymmetricKey(size: .bits256)
        let config = AppLayerConfig()

        config.pinEnabledPerDepth = try (0..<32).map { depth in
            let value = UInt8(depth == 2 ? 0 : 1)
            return try #require(try JSONEncoder().encode(value).encrypt(using: oldKey))
        }

        try config.reencrypt(from: oldKey, to: newKey)

        #expect(try decodeUInt8(config.pinEnabledPerDepth[2], using: newKey) == 0)
        #expect(try decodeUInt8(config.pinEnabledPerDepth[0], using: newKey) == 1)
        #expect(config.pinEnabledPerDepth.count == 32)
    }

    /// Every entry must stay the same length after a rotation, or the disabled slot becomes
    /// identifiable by ciphertext size alone — the whole reason the field encodes `UInt8`
    /// rather than `Bool`.
    @Test("All gate entries stay equal-length and are all rewritten")
    func gateEntriesRemainIndistinguishable() throws {
        let oldKey = SymmetricKey(size: .bits256)
        let newKey = SymmetricKey(size: .bits256)
        let config = AppLayerConfig()

        config.pinEnabledPerDepth = try (0..<32).map { depth in
            let value = UInt8(depth == 7 ? 0 : 1)
            return try #require(try JSONEncoder().encode(value).encrypt(using: oldKey))
        }
        let before = config.pinEnabledPerDepth

        try config.reencrypt(from: oldKey, to: newKey)

        #expect(Set(config.pinEnabledPerDepth.map(\.count)).count == 1)
        // Fresh nonces everywhere: no entry may survive byte-identical.
        #expect(zip(before, config.pinEnabledPerDepth).allSatisfy { $0 != $1 })
    }

    /// A stranded gate entry is re-sealed as enabled — the value `readPinEnabled(at:)`
    /// already reports for it — rather than left as unreadable garbage among live entries.
    @Test("A stranded gate entry is normalised to enabled")
    func strandedGateEntryNormalised() throws {
        let oldKey = SymmetricKey(size: .bits256)
        let newKey = SymmetricKey(size: .bits256)
        let config = AppLayerConfig()

        config.pinEnabledPerDepth = try (0..<32).map { _ in
            try #require(try JSONEncoder().encode(UInt8(1)).encrypt(using: oldKey))
        }
        // Entry 5 is sealed under a key nobody holds.
        config.pinEnabledPerDepth[5] = try #require(
            try JSONEncoder().encode(UInt8(0)).encrypt(using: SymmetricKey(size: .bits256))
        )

        try config.reencrypt(from: oldKey, to: newKey)

        #expect(try decodeUInt8(config.pinEnabledPerDepth[5], using: newKey) == 1)
        #expect(Set(config.pinEnabledPerDepth.map(\.count)).count == 1)
    }

    /// Blob metadata deliberately does not rotate — it lives on the SE-derived key. If a
    /// rotation touched it, the very failure mode Decision 2 removed would be back.
    @Test("Blob metadata is untouched by a local DB key rotation")
    func blobMetadataUnaffectedByRotation() throws {
        let oldKey  = SymmetricKey(size: .bits256)
        let newKey  = SymmetricKey(size: .bits256)
        let blobKey = SymmetricKey(size: .bits256)
        let config  = AppLayerConfig()

        try config.writeBlobSlot(9, at: 0, using: blobKey)
        try config.writeSequenceNumber(4242, at: 0, using: blobKey)

        try config.reencrypt(from: oldKey, to: newKey)

        #expect(config.readBlobSlot(at: 0, using: blobKey) == 9)
        #expect(config.readSequenceNumber(at: 0, using: blobKey) == 4242)
    }

    /// Two consecutive rotations — the multi-layer case that stranded depth-0 metadata and
    /// every gate entry before this fix.
    @Test("Fields survive consecutive rotations")
    func survivesConsecutiveRotations() throws {
        let k1 = SymmetricKey(size: .bits256)
        let k2 = SymmetricKey(size: .bits256)
        let k3 = SymmetricKey(size: .bits256)
        let config = AppLayerConfig()

        config.persistedDepth = try JSONEncoder().encode(1).encrypt(using: k1)
        config.pinEnabledPerDepth = try (0..<32).map { depth in
            try #require(try JSONEncoder().encode(UInt8(depth == 1 ? 0 : 1)).encrypt(using: k1))
        }

        try config.reencrypt(from: k1, to: k2)
        try config.reencrypt(from: k2, to: k3)

        #expect(try decodeInt(config.persistedDepth, using: k3) == 1)
        #expect(try decodeUInt8(config.pinEnabledPerDepth[1], using: k3) == 0)
    }
}

// MARK: - Decode helpers

private func decodeInt(_ data: Data?, using key: SymmetricKey) throws -> Int {
    let plain = try #require(data?.decrypt(using: key))
    return try JSONDecoder().decode(Int.self, from: plain)
}

private func decodeUInt8(_ data: Data?, using key: SymmetricKey) throws -> UInt8 {
    let plain = try #require(data?.decrypt(using: key))
    return try JSONDecoder().decode(UInt8.self, from: plain)
}

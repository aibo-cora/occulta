//
//  StagedKeyTests.swift
//  OccultaTests
//
//  Tests for the Manager.Key staged DB key rotation methods used in
//  Secure Mode activation and deactivation sequences.
//

import Testing
import Foundation
import CryptoKit
@testable import Occulta

// MARK: - Tests

@MainActor
struct StagedKeyTests {

    // MARK: - createStagedLocalDBKey

    @Test func create_returnsDifferentKeyThanCanonical() throws {
        let km = TestKeyManager()
        let canonical = try km.createHybridLocalEncryptionKey()!
        let staged = try km.createStagedLocalDBKey()
        // Staged and canonical must differ — different SE key + different random.
        #expect(canonical.withUnsafeBytes({ Data($0) }) != staged.withUnsafeBytes({ Data($0) }))
    }

    @Test func create_isIdempotent() throws {
        let km = TestKeyManager()
        let first  = try km.createStagedLocalDBKey()
        let second = try km.createStagedLocalDBKey()
        // Second call cleans up the first staged artefacts and creates fresh ones.
        // Keys must differ (different random on each call).
        #expect(first.withUnsafeBytes({ Data($0) }) != second.withUnsafeBytes({ Data($0) }))
    }

    // MARK: - commitStagedLocalDBKey

    @Test func commit_canonicalBecomesStaged() throws {
        let km = TestKeyManager()
        let stagedKey = try km.createStagedLocalDBKey()
        try km.commitStagedLocalDBKey()
        // After commit, createHybridLocalEncryptionKey() must return the same key as staged.
        let newCanonical = try km.createHybridLocalEncryptionKey()!
        #expect(newCanonical.withUnsafeBytes({ Data($0) }) == stagedKey.withUnsafeBytes({ Data($0) }))
    }

    @Test func commit_withoutCreate_throws() throws {
        let km = TestKeyManager()
        #expect(throws: (any Error).self) {
            try km.commitStagedLocalDBKey()
        }
    }

    // MARK: - rollbackStagedLocalDBKey

    @Test func rollback_canonicalUnchanged() throws {
        let km = TestKeyManager()
        let originalCanonical = try km.createHybridLocalEncryptionKey()!
        _ = try km.createStagedLocalDBKey()
        km.rollbackStagedLocalDBKey()
        // Canonical key must be the same as before staging.
        let afterRollback = try km.createHybridLocalEncryptionKey()!
        #expect(
            originalCanonical.withUnsafeBytes({ Data($0) }) ==
            afterRollback.withUnsafeBytes({ Data($0) })
        )
    }

    @Test func rollback_isNoOpWhenNothingStaged() throws {
        let km = TestKeyManager()
        let canonical = try km.createHybridLocalEncryptionKey()!
        km.rollbackStagedLocalDBKey()  // No staged key — should not throw or mutate.
        let afterRollback = try km.createHybridLocalEncryptionKey()!
        #expect(
            canonical.withUnsafeBytes({ Data($0) }) ==
            afterRollback.withUnsafeBytes({ Data($0) })
        )
    }

    @Test func rollback_preventsCommit() throws {
        let km = TestKeyManager()
        _ = try km.createStagedLocalDBKey()
        km.rollbackStagedLocalDBKey()
        // Commit after rollback must throw — staged artefacts were deleted.
        #expect(throws: (any Error).self) {
            try km.commitStagedLocalDBKey()
        }
    }

    // MARK: - deleteSupersededLocalDBArtefacts

    @Test func deleteSuperseded_isNoOp() throws {
        let km = TestKeyManager()
        let canonical = try km.createHybridLocalEncryptionKey()!
        km.deleteSupersededLocalDBArtefacts()  // Nothing staged — must not throw or mutate.
        let after = try km.createHybridLocalEncryptionKey()!
        #expect(canonical.withUnsafeBytes({ Data($0) }) == after.withUnsafeBytes({ Data($0) }))
    }

    @Test func deleteSuperseded_afterCommit_canonicalUnchanged() throws {
        let km = TestKeyManager()
        let stagedKey = try km.createStagedLocalDBKey()
        try km.commitStagedLocalDBKey()
        km.deleteSupersededLocalDBArtefacts()
        // Canonical must still be the committed staged key.
        let canonical = try km.createHybridLocalEncryptionKey()!
        #expect(canonical.withUnsafeBytes({ Data($0) }) == stagedKey.withUnsafeBytes({ Data($0) }))
    }

    // MARK: - Full rotation cycle

    @Test func fullRotation_oldKeyGone_newKeyActive() throws {
        let km = TestKeyManager()
        let original = try km.createHybridLocalEncryptionKey()!

        // Activation rotation
        let rotated = try km.createStagedLocalDBKey()
        try km.commitStagedLocalDBKey()
        km.deleteSupersededLocalDBArtefacts()

        let afterActivation = try km.createHybridLocalEncryptionKey()!
        #expect(afterActivation.withUnsafeBytes({ Data($0) }) == rotated.withUnsafeBytes({ Data($0) }))
        #expect(afterActivation.withUnsafeBytes({ Data($0) }) != original.withUnsafeBytes({ Data($0) }))
    }
}

//
//  ProtectedBlobSlotTests.swift
//  OccultaTests
//
//  Coverage for the blob-slot exclusion set that activation feeds to
//  `randomSlot(excluding:)`. Bug 46 established that the real layer (depth 0) and the
//  first duress layer (depth 1) must never have their blobs overwritten, so their slots
//  are held out of the random draw; depth-2+ blobs are expendable and stay in the pool.
//
//  An unreadable entry is skipped rather than treated as an error — see
//  `protectedBlobSlots(config:depth:blobKey:)` for why refusing to activate would protect
//  nothing. These tests pin that behaviour so it is not "fixed" back into a throw.
//
//  Fully deterministic: since Bug 76 moved blob metadata onto an SE-derived key passed in
//  explicitly, these exercise the real code paths with an arbitrary test key and need no
//  Secure Enclave and no availability guard.
//

import Testing
import Foundation
import CryptoKit
import SwiftData
@testable import Occulta

// MARK: - Helpers

/// A config whose blob-slot array is entirely random filler — the state a freshly seeded
/// row starts in, and the state a stranded entry presents as.
private func makeFillerConfig() -> AppLayerConfig {
    AppLayerConfig()
}

private func testBlobKey() -> SymmetricKey {
    SymmetricKey(size: .bits256)
}

// MARK: - Tests

@Suite("Blob slot exclusion")
struct ProtectedBlobSlotTests {

    @Test("Depth 0 activation has nothing to protect")
    func depthZeroReturnsEmpty() {
        let slots = Manager.Security.protectedBlobSlots(
            config: makeFillerConfig(), depth: 0, blobKey: testBlobKey()
        )
        #expect(slots.isEmpty)
    }

    /// The case that matters most: an unreadable depth-0 index must not block activation.
    /// Its blob is already unreachable — `deactivateSecureMode` locates the blob through
    /// this same read — so excluding its slot would protect a payload nothing can pop, at
    /// the cost of the user's decoy layer.
    @Test("Unreadable entries are skipped, not treated as an error")
    func unreadableEntriesSkipped() {
        let config = makeFillerConfig()
        let key    = testBlobKey()

        #expect(Manager.Security.protectedBlobSlots(config: config, depth: 1, blobKey: key).isEmpty)
        #expect(Manager.Security.protectedBlobSlots(config: config, depth: 2, blobKey: key).isEmpty)
    }

    /// An entry sealed under a *different* key — e.g. one this install has not migrated off
    /// the old local-DB-key scheme yet — reads as absent rather than throwing.
    @Test("An entry under the wrong key reads as absent")
    func wrongKeyReadsAsAbsent() throws {
        let config = makeFillerConfig()
        try config.writeBlobSlot(4, at: 0, using: testBlobKey())

        let slots = Manager.Security.protectedBlobSlots(
            config: config, depth: 2, blobKey: testBlobKey()
        )
        #expect(slots.isEmpty)
    }

    @Test("Both protected slots are excluded when both are readable")
    func bothProtectedSlotsExcluded() throws {
        let config = makeFillerConfig()
        let key    = testBlobKey()
        try config.writeBlobSlot(3, at: 0, using: key)
        try config.writeBlobSlot(9, at: 1, using: key)

        #expect(Manager.Security.protectedBlobSlots(config: config, depth: 2, blobKey: key) == [3, 9])
    }

    /// `reEnablePIN`'s coercion-acceptance path creates the depth 1→2 layer with no key
    /// rotation and no blob push, so `sealedBlobSlots[1]` legitimately stays filler. A
    /// depth-2 activation must still protect the readable depth-0 slot.
    @Test("A readable slot is still excluded when its neighbour is not")
    func readableSlotExcludedAlongsideUnreadable() throws {
        let config = makeFillerConfig()
        let key    = testBlobKey()
        try config.writeBlobSlot(7, at: 0, using: key)

        #expect(Manager.Security.protectedBlobSlots(config: config, depth: 2, blobKey: key) == [7])
    }

    /// Only depths 0 and 1 are protected — depth-2+ blobs are expendable and must stay in
    /// the pool so the random draw keeps as many candidates as possible.
    @Test("Depth-2 slot is not excluded at a depth-3 activation")
    func expendableSlotsNotExcluded() throws {
        let config = makeFillerConfig()
        let key    = testBlobKey()
        try config.writeBlobSlot(3,  at: 0, using: key)
        try config.writeBlobSlot(9,  at: 1, using: key)
        try config.writeBlobSlot(11, at: 2, using: key)

        let slots = Manager.Security.protectedBlobSlots(config: config, depth: 3, blobKey: key)

        #expect(slots == [3, 9])
        #expect(!slots.contains(11))
    }
}

// MARK: - Blob metadata key migration

@Suite("Bug 76 — blob metadata key migration")
struct BlobMetadataMigrationTests {

    /// Installs that activated before blob metadata moved to the SE key hold entries under
    /// whatever local DB key was canonical then. Reading those with the SE key fails, so
    /// without this migration a currently-reachable blob would be silently orphaned.
    @Test("Entries under the old local DB key are moved onto the blob key")
    func migratesOldEntries() throws {
        let dbKey   = SymmetricKey(size: .bits256)
        let blobKey = SymmetricKey(size: .bits256)
        let config  = AppLayerConfig()

        // Seed the pre-migration state: sealed under the local DB key.
        try config.writeBlobSlot(5, at: 0, using: dbKey)
        try config.writeSequenceNumber(1234, at: 0, using: dbKey)
        try #require(config.readBlobSlot(at: 0, using: blobKey) == nil)

        let moved = config.migrateBlobMetadata(fromLocalDBKey: dbKey, toBlobKey: blobKey)

        #expect(moved)
        #expect(config.readBlobSlot(at: 0, using: blobKey) == 5)
        #expect(config.readSequenceNumber(at: 0, using: blobKey) == 1234)
    }

    @Test("Already-migrated entries are left alone and report no change")
    func idempotent() throws {
        let dbKey   = SymmetricKey(size: .bits256)
        let blobKey = SymmetricKey(size: .bits256)
        let config  = AppLayerConfig()
        try config.writeBlobSlot(6, at: 1, using: blobKey)

        let before = config.sealedBlobSlots
        let moved  = config.migrateBlobMetadata(fromLocalDBKey: dbKey, toBlobKey: blobKey)

        #expect(!moved)
        #expect(config.sealedBlobSlots == before)
        #expect(config.readBlobSlot(at: 1, using: blobKey) == 6)
    }

    /// Entries readable under neither key are stranded by an earlier rotation. Nothing can
    /// recover them, and rewriting them would only make dead entries look freshly written.
    @Test("Filler and stranded entries are untouched")
    func strandedEntriesUntouched() {
        let config = AppLayerConfig()
        let before = config.sealedBlobSlots

        let moved = config.migrateBlobMetadata(
            fromLocalDBKey: SymmetricKey(size: .bits256),
            toBlobKey:      SymmetricKey(size: .bits256)
        )

        #expect(!moved)
        #expect(config.sealedBlobSlots == before)
    }

    /// A half-migrated row must converge, not stall: one live entry under each key.
    @Test("A mixed row migrates only what still needs it")
    func mixedRowConverges() throws {
        let dbKey   = SymmetricKey(size: .bits256)
        let blobKey = SymmetricKey(size: .bits256)
        let config  = AppLayerConfig()
        try config.writeBlobSlot(2, at: 0, using: dbKey)    // old scheme
        try config.writeBlobSlot(8, at: 1, using: blobKey)  // already migrated

        let moved = config.migrateBlobMetadata(fromLocalDBKey: dbKey, toBlobKey: blobKey)

        #expect(moved)
        #expect(config.readBlobSlot(at: 0, using: blobKey) == 2)
        #expect(config.readBlobSlot(at: 1, using: blobKey) == 8)
    }
}

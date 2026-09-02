//
//  LayerArrayUniformityTests.swift
//  OccultaTests
//
//  Phase 0 for Bug 86 — executable reproduction, written before the fix.
//
//  `ensurePadded()` pads three arrays to 32 entries so that, in the field's own words,
//  "array length is forensically constant". Array *length* was made constant; element
//  length was not, and element length is what names the occupied depths.
//
//  These began wrapped in `withKnownIssue` so the suite stayed green while the bug was
//  open. Each flipped to failing the moment the fix landed — `withKnownIssue` fails when
//  no issue is recorded — and the wrappers came off then, leaving the assertions as
//  regression guards. The migration tests at the bottom cover the conversion itself.
//
//  The two blob-array tests need no Secure Enclave: `writeBlobSlot` and
//  `writeSequenceNumber` both take their key explicitly, and `encrypt(using:)` uses the
//  passed key directly without touching the key manager. They run on CI runners.
//

import Testing
import Foundation
import CryptoKit
import SwiftData
@testable import Occulta

@Suite("Bug 86 — padded array element uniformity")
struct LayerArrayUniformityTests {

    /// A real slot index for depths 0–9 seals to 29 bytes against 30-byte filler, so a
    /// 29-byte element proves a layer exists at that depth. One-sided — slots 10–31 seal
    /// to 30 and hide — so roughly 31% of layers are exposed this way.
    @Test("Blob-slot elements are all one length")
    func blobSlotElementsAreUniform() throws {
        let config = AppLayerConfig()
        let key    = SymmetricKey(size: .bits256)

        // Slot 7: a single JSON digit, which is the exposed case.
        try config.writeBlobSlot(7, at: 2, using: key)

        let lengths = Set(config.sealedBlobSlots.map(\.count))
        #expect(lengths.count == 1, """
            sealedBlobSlots holds \(lengths.sorted()) distinct element lengths. Element \
            length is readable from the store file with no key, and the array is indexed \
            by depth — so an element that differs from the filler names an occupied depth.
            """)
    }

    /// The severe one. Sequence numbers are `Int(UInt32)`, so ~98% of real entries seal to
    /// 37 or 38 bytes against 30-byte filler. A real entry hides only when its sequence
    /// number has exactly two digits: 90 values out of 2³².
    @Test("Sequence-number elements are all one length")
    func sequenceNumberElementsAreUniform() throws {
        let config = AppLayerConfig()
        let key    = SymmetricKey(size: .bits256)

        // A representative draw from randomSequenceNumber()'s range — 10 digits, which is
        // 76.7% of the distribution.
        try config.writeSequenceNumber(3_000_000_000, at: 2, using: key)

        let lengths = Set(config.layerSequenceNumbers.map(\.count))
        #expect(lengths.count == 1, """
            layerSequenceNumbers holds \(lengths.sorted()) distinct element lengths. \
            This marks an occupied depth from the moment a layer is created, whether or \
            not any contact was ever classified.
            """)
    }

    /// Both arrays are padded by the same `ensurePadded()` against the same `fillerSize`
    /// literal, and neither matches. Pinning the constant against the values that are
    /// actually written is the check that would have caught this — and the one to keep
    /// once `fillerSize` is derived from a codec instead of hardcoded.
    @Test("Filler size matches what the writers actually produce")
    func fillerSizeMatchesRealEntries() throws {
        let config = AppLayerConfig()
        let key    = SymmetricKey(size: .bits256)
        let fillerLength = try #require(config.sealedBlobSlots.first?.count)

        try config.writeBlobSlot(7, at: 0, using: key)
        try config.writeSequenceNumber(3_000_000_000, at: 1, using: key)

        #expect(config.sealedBlobSlots[0].count == fillerLength,
                "a written slot must be the same size as the filler it replaces")
        #expect(config.layerSequenceNumbers[1].count == fillerLength,
                "a written sequence number must be the same size as the filler it replaces")
    }

    /// `pinEnabledEntrySize` must equal what a real entry actually seals to, because the
    /// fallback filler is sized from it. A constant that drifts from the format it
    /// describes is this whole bug — and this array's fallback previously borrowed the blob
    /// arrays' `fillerSize`, which is drift by construction: it would have grown from a
    /// 1-byte outlier to a 4-byte one the moment that constant moved for the blob arrays.
    ///
    /// Enclave-free: the property is the size arithmetic, so a local key is enough.
    @Test("pinEnabledEntrySize matches what a real entry seals to")
    func pinEnabledEntrySizeIsAccurate() throws {
        let key = SymmetricKey(size: .bits256)
        for value in [UInt8(0), UInt8(1)] {
            let sealed = try AES.GCM.seal(JSONEncoder().encode(value), using: key).combined
            #expect(sealed?.count == AppLayerConfig.pinEnabledEntrySize, """
                A gate entry for \(value) seals to \(sealed?.count ?? -1), but the fallback \
                filler is sized \(AppLayerConfig.pinEnabledEntrySize). Any difference names \
                the depth whose entry could not be encrypted.
                """)
        }
    }

    /// **Fixed** — Bug 86's amendment, now a regression guard rather than a reproduction.
    ///
    /// The legacy-upgrade path in `Manager.Security.init` used to hand-roll
    /// `JSONEncoder().encode(false)`, which sealed to 33 bytes against every other entry's
    /// 29 — identifying the disabled depth by size alone, the exact hazard this array's own
    /// doc comment exists to prevent. It failed twice over: `readPinEnabled` decodes
    /// `UInt8`, could not parse a `Bool` plaintext, and fell back to `true`, so the gate
    /// that branch means to keep down came straight back up.
    ///
    /// It now routes through `writePinEnabled`, which encodes `UInt8` like every other
    /// writer.
    ///
    /// Needs the Enclave: this path and the array's filler both go through ambient
    /// `encrypt()`.
    @Test("The legacy PIN-gate upgrade writes a readable, correctly-sized entry",
          .enabled(if: secureEnclaveAvailable()))
    @MainActor
    func legacyPinGateUpgradeIsUniformAndReadable() throws {
        let schema = Schema([AppLayerConfig.self])
        let container = try ModelContainer(
            for: schema,
            configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)]
        )
        let context = ModelContext(container)

        // A pre-upgrade row: no per-depth array, and the legacy scalar says the gate was down.
        let config = AppLayerConfig()
        config.pinEnabledPerDepth = []
        config.pinEnabled = try JSONEncoder().encode(false).encrypt()
        try config.writePersistedDepth(0)
        context.insert(config)
        try context.save()

        // Constructing Manager.Security runs the upgrade path under test.
        _ = Manager.Security(modelContainer: container)

        let upgraded = try #require(try context.fetch(FetchDescriptor<AppLayerConfig>()).first)
        let lengths  = Set(upgraded.pinEnabledPerDepth.map(\.count))

        #expect(lengths.count == 1, """
            pinEnabledPerDepth holds \(lengths.sorted()) distinct element lengths. The \
            oversized one is the depth whose PIN gate was disabled — which is exactly \
            what this array's own doc comment says must not be identifiable by size.
            """)
        #expect(upgraded.readPinEnabled(at: 0) == false, """
            readPinEnabled decodes UInt8 and cannot parse a Bool plaintext, so it falls \
            back to true. The gate the upgrade meant to keep down comes back up.
            """)
    }
}

private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

// MARK: - Migration

@MainActor
private func makeConfigContainer() throws -> ModelContainer {
    let schema = Schema([AppLayerConfig.self])
    return try ModelContainer(
        for: schema,
        configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)]
    )
}

/// Seeds a config whose blob arrays are in the OLD format: legacy JSON entries at `depth`,
/// 30-byte random filler everywhere else, exactly as a pre-upgrade install has them.
@MainActor
private func seedLegacyConfig(
    slot: Int, sequenceNumber: Int, at depth: Int,
    blobKey: SymmetricKey, in context: ModelContext
) throws {
    let config = AppLayerConfig()
    var slots = (0..<32).map { _ in Data((0..<30).map { _ in UInt8.random(in: 0...255) }) }
    var seqs  = slots
    slots[depth] = try JSONEncoder().encode(slot).encrypt(using: blobKey)!
    seqs[depth]  = try JSONEncoder().encode(sequenceNumber).encrypt(using: blobKey)!
    config.sealedBlobSlots      = slots
    config.layerSequenceNumbers = seqs
    context.insert(config)
    try context.save()
}

@Suite("Bug 86 — blob array fixed-width migration", .serialized)
@MainActor
struct BlobArrayFixedWidthMigrationTests {

    /// The catastrophic guard. Filler and an unreadable real entry are indistinguishable, so
    /// the pass rewrites anything it cannot decrypt as fresh filler. Without a usable key
    /// *every* element looks undecryptable, and all 32 entries of both arrays would be
    /// replaced — destroying every layer's blob metadata on a device where nothing was wrong.
    @Test("With no Secure Mode key the pass is a complete no-op")
    func noKeyMeansNoOp() throws {
        let container  = try makeConfigContainer()
        let context    = ModelContext(container)
        let keyManager = TestKeyManager()
        let seKey      = try #require(try keyManager.deriveSecureModeKey())
        let blobKey    = AppLayerConfig.blobMetadataKey(from: seKey)
        try seedLegacyConfig(slot: 7, sequenceNumber: 3_000_000_000, at: 2,
                             blobKey: blobKey, in: context)

        let before = try #require(try context.fetch(FetchDescriptor<AppLayerConfig>()).first)
        let slotsBefore = before.sealedBlobSlots
        let seqsBefore  = before.layerSequenceNumbers

        keyManager.simulatesSecureModeKeyUnavailable = true
        _ = Manager.Security(modelContainer: container, keyManager: keyManager)

        let after = try #require(try context.fetch(FetchDescriptor<AppLayerConfig>()).first)
        #expect(after.sealedBlobSlots == slotsBefore, """
            Without a usable key the pass must touch nothing. Rewriting here replaces every \
            element with filler, and deactivation can then pop no blob at any depth — \
            sensitive contacts unrecoverable, for every layer at once.
            """)
        #expect(after.layerSequenceNumbers == seqsBefore)
    }

    /// The conversion itself: real entries survive with their values, filler is resized, and
    /// the array comes out uniform — which is the point.
    @Test("Legacy arrays converge to one element length, values intact")
    func legacyArraysConverge() throws {
        let container  = try makeConfigContainer()
        let context    = ModelContext(container)
        let keyManager = TestKeyManager()
        let seKey      = try #require(try keyManager.deriveSecureModeKey())
        let blobKey    = AppLayerConfig.blobMetadataKey(from: seKey)
        try seedLegacyConfig(slot: 7, sequenceNumber: 3_000_000_000, at: 2,
                             blobKey: blobKey, in: context)

        _ = Manager.Security(modelContainer: container, keyManager: keyManager)

        let after = try #require(try context.fetch(FetchDescriptor<AppLayerConfig>()).first)
        #expect(Set(after.sealedBlobSlots.map(\.count)).count == 1,
                "slots: \(Set(after.sealedBlobSlots.map(\.count)).sorted())")
        #expect(Set(after.layerSequenceNumbers.map(\.count)).count == 1,
                "seqnums: \(Set(after.layerSequenceNumbers.map(\.count)).sorted())")
        #expect(after.readBlobSlot(at: 2, using: blobKey) == 7,
                "the slot index must survive the conversion verbatim")
        #expect(after.readSequenceNumber(at: 2, using: blobKey) == 3_000_000_000, """
            The sequence number must survive verbatim. It is validated on pop, and a mismatch \
            makes deactivation substitute an empty payload — sensitive contacts unrecoverable.
            """)
    }

    /// It runs on every launch, so a second pass must not re-randomise filler — that would
    /// churn the WAL on every start and rewrite 32 entries for nothing.
    @Test("A second run changes nothing")
    func migrationIsIdempotent() throws {
        let container  = try makeConfigContainer()
        let context    = ModelContext(container)
        let keyManager = TestKeyManager()
        let seKey      = try #require(try keyManager.deriveSecureModeKey())
        let blobKey    = AppLayerConfig.blobMetadataKey(from: seKey)
        try seedLegacyConfig(slot: 3, sequenceNumber: 42, at: 1, blobKey: blobKey, in: context)

        _ = Manager.Security(modelContainer: container, keyManager: keyManager)
        let first = try #require(try context.fetch(FetchDescriptor<AppLayerConfig>()).first)
        let slotsAfterFirst = first.sealedBlobSlots
        let seqsAfterFirst  = first.layerSequenceNumbers

        _ = Manager.Security(modelContainer: container, keyManager: keyManager)
        let second = try #require(try context.fetch(FetchDescriptor<AppLayerConfig>()).first)

        #expect(second.sealedBlobSlots == slotsAfterFirst,
                "a converted array must not be rewritten on the next launch")
        #expect(second.layerSequenceNumbers == seqsAfterFirst)
    }
}

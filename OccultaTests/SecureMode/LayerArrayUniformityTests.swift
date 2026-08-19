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
//  These assertions are wrapped in `withKnownIssue`, so the suite stays green while the
//  bug is open and each test flips to failing the moment it is fixed — at which point the
//  wrapper should be removed and the assertion kept as the regression guard.
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
        withKnownIssue("Bug 86: fillerSize is 30, a single-digit slot index seals to 29") {
            #expect(lengths.count == 1, """
                sealedBlobSlots holds \(lengths.sorted()) distinct element lengths. Element \
                length is readable from the store file with no key, and the array is indexed \
                by depth — so an element that differs from the filler names an occupied depth.
                """)
        }
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
        withKnownIssue("Bug 86: fillerSize is 30, a 32-bit sequence number seals to 37–38") {
            #expect(lengths.count == 1, """
                layerSequenceNumbers holds \(lengths.sorted()) distinct element lengths. \
                This marks an occupied depth from the moment a layer is created, whether or \
                not any contact was ever classified.
                """)
        }
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

        withKnownIssue("Bug 86: fillerSize = 30 is a literal, unrelated to either encoding") {
            #expect(config.sealedBlobSlots[0].count == fillerLength,
                    "a written slot must be the same size as the filler it replaces")
            #expect(config.layerSequenceNumbers[1].count == fillerLength,
                    "a written sequence number must be the same size as the filler it replaces")
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

//
//  LayerArrayUniformityTests.swift
//  OccultaTests
//
//  Bug 86 — `pinEnabledPerDepth` element-length uniformity.
//
//  Originally covered three padded arrays (`sealedBlobSlots`, `layerSequenceNumbers`,
//  `pinEnabledPerDepth`) plus a fixed-width migration for the first two. The blob-slot
//  and sequence-number arrays, their migration, and their tests were removed along with
//  the rest of the blob mechanism (Removal Stage 2, `plan.md`) — `pinEnabledPerDepth`'s
//  own uniformity requirement is unrelated to that removal and stays live.
//

import Testing
import Foundation
import CryptoKit
import SwiftData
@testable import Occulta

@Suite("Bug 86 — padded array element uniformity")
struct LayerArrayUniformityTests {

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
          .ambientTestKeyManager)
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


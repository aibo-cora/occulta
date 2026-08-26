//
//  LayerStoreMaintenanceTests.swift
//  OccultaTests
//
//  Guards the maintenance-rewrite cadence (Bug 71). The three cadence tests need no Secure
//  Enclave — they assert a constant and a threshold comparison. The fourth does, and the
//  header used to claim otherwise for the whole file: `maintain()` rewrites through
//  `writeNoOpFile`, which derives a key from `Manager.Key()` directly and returns without
//  writing when there is none. On a runner with no Enclave that turns "an older file is
//  rewritten" into a failure rather than a skip. `LayerStore`'s only seam is its backend, so
//  this is gated rather than injected.
//

import Testing
import Foundation
@testable import Occulta

private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

@Suite("LayerStore — maintenance cadence")
struct LayerStoreMaintenanceTests {

    @Test("Maintenance threshold falls inside the 18–30 h jitter window")
    func maxAgeIsJitteredWithinWindow() {
        let maxAge = Manager.LayerStore.maxAge

        #expect(maxAge >= 18 * 3_600)
        #expect(maxAge <= 30 * 3_600)
    }

    @Test("Maintenance threshold is not the old fixed 24 h constant")
    func maxAgeIsNotTheFixedConstant() {
        // The bug was that 86_400 exactly was a fingerprint. Landing on it by chance is
        // possible but has measure zero over a continuous range, so an exact hit means
        // the jitter was reverted rather than that we got unlucky.
        #expect(Manager.LayerStore.maxAge != 86_400)
    }

    @Test("Threshold is stable within a process, so repeated maintain() calls agree")
    func maxAgeIsStableAcrossReads() {
        // The reason this is `static let` and not a per-call draw: `maintain()` runs on
        // every foreground, and a fresh draw each time would let the lowest draw win,
        // collapsing the window back toward its 18 h floor.
        let first  = Manager.LayerStore.maxAge
        let second = Manager.LayerStore.maxAge

        #expect(first == second)
    }

    @Test("A file younger than the threshold is not rewritten; an older one is",
          .enabled(if: secureEnclaveAvailable()))
    func maintainRespectsTheThreshold() throws {
        let maxAge = Manager.LayerStore.maxAge
        let marker = Data(repeating: 0xAB, count: 8)

        let fresh = InMemoryLayerStoreBackend()
        try fresh.write(marker)
        fresh.modificationDate = Date().addingTimeInterval(-(maxAge - 3_600))

        Manager.LayerStore(backend: fresh).maintain()
        let afterFresh = try fresh.read()
        #expect(afterFresh == marker, "A file inside the window must not be rewritten")

        let stale = InMemoryLayerStoreBackend()
        try stale.write(marker)
        stale.modificationDate = Date().addingTimeInterval(-(maxAge + 3_600))

        Manager.LayerStore(backend: stale).maintain()
        let afterStale = try stale.read()
        #expect(afterStale != marker, "A file past the window must be rewritten")
    }
}

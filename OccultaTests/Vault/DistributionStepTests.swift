//
//  DistributionStepTests.swift
//  OccultaTests
//
//  The Backup Recovery screen's button decides its next step through
//  `VaultShardSetup.nextStep`. A locked vault must short-circuit before anything that
//  reads the vault: a locked vault reads as "no distribution", which opened the education
//  sheet over an existing distribution (`bugs.md` Bug 150).
//

import Testing
@testable import Occulta

@Suite("Backup Recovery — the button's next step")
struct DistributionStepTests {

    @Test("Locked: unlock first, without reading the distribution or the recipients")
    func lockedUnlocksFirst() {
        var read = false
        let step = VaultShardSetup.nextStep(
            isUnlocked: false,
            hasDistribution: { read = true; return false }(),
            dropsTrustee: { read = true; return true }()
        )
        #expect(step == .unlock)
        #expect(!read, "nothing sealed with the vault key is read while locked")
    }

    @Test("Unlocked, no distribution yet: explain first")
    func firstDistributionExplains() {
        #expect(VaultShardSetup.nextStep(isUnlocked: true, hasDistribution: false, dropsTrustee: false) == .explain)
    }

    @Test("Unlocked, leaving someone out: confirm the key replacement")
    func droppingTrusteeConfirms() {
        #expect(VaultShardSetup.nextStep(isUnlocked: true, hasDistribution: true, dropsTrustee: true) == .confirmRemoval)
    }

    @Test("Unlocked, same or more trustees: queue")
    func otherwiseQueues() {
        #expect(VaultShardSetup.nextStep(isUnlocked: true, hasDistribution: true, dropsTrustee: false) == .queue)
    }
}

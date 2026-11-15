//
//  GroupOrphanPurgeTests.swift
//  OccultaTests
//
//  Coverage for the Bug 75 repair pass, `ContactManager.purgeUnreadableGroups()`.
//
//  `Group.reencrypt` stops new groups from being stranded by a key rotation, but it cannot
//  help rows already stranded before it existed. Those are unopenable, unmessageable and
//  undeletable through the UI (every path resolves a group via `readID()`), so they sit in
//  the store forever showing up only as an inflated count. This pass removes them.
//
//  The dangerous failure mode is over-deletion: judged against the wrong key — or against no
//  key at all — every group looks stranded and the whole table goes. "No key" cannot reach
//  the row loop, because the key is a required parameter rather than something the sweep
//  derives internally; the call site in `OccultaApp` is where a failed derivation stops the
//  sweep. A key that is there but doesn't open the store is refused by the sweep itself
//  (Bug 191, a test host on legacy keys over a resealed store): it must first open the
//  config row's `persistedDepth`.
//

import Testing
import Foundation
import SwiftData
import CryptoKit
@testable import Occulta


// MARK: - Helpers

private func canonicalKey() -> SymmetricKey? {
    try? Manager.Ambient.keyManager.createHybridLocalEncryptionKey()
}

/// - Parameter seedingConfig: Whether the store holds the config row a real one always does, sealed under the ambient key.
@MainActor
private func makeManager(seedingConfig: Bool = true) throws -> ContactManager {
    let schema = Schema([
        Group.self,
        Contact.Profile.self,
        Contact.Profile.PhoneNumber.self,
        Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self,
        Contact.Profile.URLAddress.self,
        Contact.Profile.Key.self,
        AppLayerConfig.self,
    ])
    let container = try ModelContainer(
        for: schema,
        configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)]
    )
    let security = Manager.Security(modelContainer: container, enabled: false)
    let manager  = ContactManager(modelContainer: container, security: security)
    if seedingConfig {
        manager.modelContext.insert(AppLayerConfig.seeded())
        try manager.modelContext.save()
    }
    return manager
}

/// Strands a group by overwriting its ID with ciphertext nobody holds the key for — the same
/// end state as a rotation whose superseded key Step 11 deleted. `Group.reencrypt` (the
/// mechanism that used to produce this state via an actual rotation) was removed along with
/// the rest of Secure Mode's key-rotation machinery (Removal Stage 3, `plan.md`), so this
/// writes stranded ciphertext directly instead.
private func strand(_ group: Group) {
    group.encryptedID = Data([0xDE, 0xAD, 0xBE, 0xEF])
}

// MARK: - Tests

/// Runs under `.ambientTestKeyManager`: `createGroup` seals with the ambient local key.
@Suite("Bug 75 — orphaned group purge", .ambientTestKeyManager)
@MainActor
struct GroupOrphanPurgeTests {

    @Test("A stranded group is removed and a healthy one is kept", .ambientTestKeyManager)
    func removesOnlyStrandedGroups() throws {
        let key     = try #require(canonicalKey())
        let manager = try makeManager()

        let healthy = try manager.createGroup(name: "Healthy")
        try healthy.addMember("alice", atDepth: 0)
        let healthyID = try #require(healthy.readID())

        let doomed = try manager.createGroup(name: "Stranded")
        strand(doomed)
        try #require(doomed.readID() == nil)

        try manager.purgeUnreadableGroups(using: key)

        let survivors = try manager.allGroups()
        #expect(survivors.count == 1)
        #expect(survivors.first?.readID() == healthyID)
        #expect(survivors.first?.readName() == "Healthy")
    }

    /// Every group stranded, under a key that does open the store: they all go. This is the Bug 75
    /// repair for a store whose groups were all left behind by a rotation.
    @Test("All groups stranded — every row goes, none left behind", .ambientTestKeyManager)
    func removesAllWhenAllStranded() throws {
        let key     = try #require(canonicalKey())
        let manager = try makeManager()
        for name in ["One", "Two", "Three"] {
            let group = try manager.createGroup(name: name)
            strand(group)
        }

        try manager.purgeUnreadableGroups(using: key)

        #expect(try manager.allGroups().isEmpty)
    }

    /// Bug 191. A test host that skips the launch sequence derives keys the resealed store isn't sealed under,
    /// so judged against them every group looks stranded. The purge must delete nothing.
    @Test("A key that doesn't open the store deletes nothing", .ambientTestKeyManager)
    func mismatchedKeyDeletesNothing() throws {
        let manager = try makeManager()
        for name in ["One", "Two", "Three"] {
            _ = try manager.createGroup(name: name)
        }
        let wrongKey = SymmetricKey(size: .bits256)

        #expect(throws: ContactManager.Errors.keyDoesNotOpenStore) {
            try manager.purgeUnreadableGroups(using: wrongKey)
        }

        #expect(try manager.allGroups().count == 3)
    }

    @Test("A store with no config row deletes nothing", .ambientTestKeyManager)
    func noConfigRowDeletesNothing() throws {
        let key     = try #require(canonicalKey())
        let manager = try makeManager(seedingConfig: false)
        let group   = try manager.createGroup(name: "One")
        strand(group)

        #expect(throws: ContactManager.Errors.keyDoesNotOpenStore) {
            try manager.purgeUnreadableGroups(using: key)
        }

        #expect(try manager.allGroups().count == 1)
    }

    @Test("A config row with no persisted depth deletes nothing", .ambientTestKeyManager)
    func noPersistedDepthDeletesNothing() throws {
        let key     = try #require(canonicalKey())
        let manager = try makeManager()
        let config  = try #require(try manager.modelContext.fetch(FetchDescriptor<AppLayerConfig>()).first)
        config.persistedDepth = nil
        let group   = try manager.createGroup(name: "One")
        strand(group)

        #expect(throws: ContactManager.Errors.keyDoesNotOpenStore) {
            try manager.purgeUnreadableGroups(using: key)
        }

        #expect(try manager.allGroups().count == 1)
    }

    @Test("An empty store is a no-op", .ambientTestKeyManager)
    func emptyStoreIsNoOp() throws {
        let key     = try #require(canonicalKey())
        let manager = try makeManager()

        try manager.purgeUnreadableGroups(using: key)

        #expect(try manager.allGroups().isEmpty)
    }

    @Test("Repeated sweeps are idempotent and leave healthy groups alone", .ambientTestKeyManager)
    func idempotent() throws {
        let key     = try #require(canonicalKey())
        let manager = try makeManager()
        let healthy = try manager.createGroup(name: "Healthy")
        try healthy.addMember("alice", atDepth: 0)
        let doomed  = try manager.createGroup(name: "Stranded")
        strand(doomed)

        try manager.purgeUnreadableGroups(using: key)
        try manager.purgeUnreadableGroups(using: key)
        try manager.purgeUnreadableGroups(using: key)

        let survivors = try manager.allGroups()
        #expect(survivors.count == 1)
        #expect(survivors.first?.members(atDepth: 0) == ["alice"])
    }
}

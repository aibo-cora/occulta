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
//  key at all — every group looks stranded and the whole table goes. That is handled by
//  making the key a required parameter rather than something the sweep derives internally,
//  so "no key" cannot reach the row loop at all; the call site in `OccultaApp` is where a
//  failed derivation stops the sweep. `removesAllWhenAllStranded` documents the honest
//  consequence of supplying a key that does not match the rows.
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

@MainActor
private func makeManager() throws -> ContactManager {
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
    return ContactManager(modelContainer: container, security: security)
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

    /// Documents the consequence of a mismatched key rather than asserting a guard: judged
    /// against a key that encrypted none of them, every row is stranded and every row goes.
    /// This is why the key is a required parameter and why the call site refuses to run the
    /// sweep at all when derivation fails — there is no in-function guard to test.
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

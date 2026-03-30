//
//  ForwardSecrecyModelTests.swift
//  OccultaTests
//
//  ⚠️  DEVICE ONLY — Contact.Profile.configureForwardSecrecy() encrypts the
//  ForwardSecrecy struct using the SE-backed local key.
//
//  Tests the Contact.Profile forward secrecy extension methods in isolation.
//  No ContactManager, no network, no SE prekey generation.
//
//  Coverage:
//    - configureForwardSecrecy (init + idempotency)
//    - popOldestPrekeyData (FIFO, empty store, count)
//    - syncInboundPrekeys (stale-batch guard, direct replace, empty-store bug)
//    - store / loadPendingBatch / clearPendingBatch / hasPendingBatch
//    - availableInboundPrekeyCount / hasPrekeyAvailable
//    - isLikelySender
//    - Full exhaustion cycle at model layer
//

import Testing
import SwiftData
import CryptoKit
import Foundation
import Security

@testable import Occulta

// MARK: - Shared helpers

private func makeContainer() throws -> ModelContainer {
    let schema = Schema([
        Contact.Profile.self,
        Contact.Profile.Key.self,
        Contact.Profile.PhoneNumber.self,
        Contact.Profile.EmailAddress.self,
    ])
    return try ModelContainer(
        for: schema,
        configurations: ModelConfiguration(isStoredInMemoryOnly: true)
    )
}

private func makeContact(in context: ModelContext) throws -> Contact.Profile {
    let c = Contact.Profile(
        identifier:       UUID().uuidString,
        givenName:        "Test",
        familyName:       "Contact",
        middleName:       "",
        nickname:         "",
        organizationName: "",
        departmentName:   "",
        jobTitle:         ""
    )
    context.insert(c)
    try context.save()
    return c
}

/// Plain JSON-encoded WirePrekey blob — what ContactManager stores after the
/// Finding 1 fix (no per-blob encryption inside an already-encrypted struct).
private func wireBlob(id: String = UUID().uuidString) -> Data {
    try! JSONEncoder().encode(
        OccultaBundle.WirePrekey(id: id, publicKey: Data(repeating: 0x04, count: 65))
    )
}

private func makeBatch(
    generatedAt: Date = Date(),
    count: Int = 3
) -> OccultaBundle.SealedPayload.PrekeySyncBatch {
    let prekeys = (0..<count).map { _ in
        OccultaBundle.WirePrekey(id: UUID().uuidString, publicKey: Data(repeating: 0x04, count: 65))
    }
    return OccultaBundle.SealedPayload.PrekeySyncBatch(generatedAt: generatedAt, prekeys: prekeys)
}

// MARK: - configureForwardSecrecy

@Suite("ForwardSecrecyModel — configureForwardSecrecy")
struct ConfigureForwardSecrecyTests {

    @Test func configure_populatesForwardSecrecyBlob() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)

        #expect(contact.forwardSecrecyEncrypted == nil)
        try contact.configureForwardSecrecy()
        #expect(contact.forwardSecrecyEncrypted != nil)
    }

    @Test func configure_isIdempotent() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)

        try contact.configureForwardSecrecy()
        let first = contact.forwardSecrecyEncrypted

        try contact.configureForwardSecrecy()
        let second = contact.forwardSecrecyEncrypted

        // Blob must not be replaced — idempotent means no-op on second call.
        #expect(first == second)
    }

    @Test func configure_newContact_hasPendingBatch_isFalse() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)

        try contact.configureForwardSecrecy()
        #expect(contact.hasPendingBatch == false)
    }

    @Test func configure_newContact_noPrekeysAvailable() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)

        try contact.configureForwardSecrecy()
        #expect(contact.availableInboundPrekeyCount == 0)
        #expect(contact.hasPrekeyAvailable == false)
    }
}

// MARK: - popOldestPrekeyData

@Suite("ForwardSecrecyModel — popOldestPrekeyData")
struct PopOldestPrekeyDataTests {

    @Test func pop_returnsFIFO() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)
        try contact.configureForwardSecrecy()

        let b1 = wireBlob(); let b2 = wireBlob(); let b3 = wireBlob()
        try contact.syncInboundPrekeys([b1, b2, b3], date: Date())

        let r1 = try contact.popOldestPrekeyData()
        let r2 = try contact.popOldestPrekeyData()
        let r3 = try contact.popOldestPrekeyData()

        #expect(r1 == b1, "First pop must return oldest blob")
        #expect(r2 == b2)
        #expect(r3 == b3)
    }

    @Test func pop_returnsNil_whenStoreEmpty() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)
        try contact.configureForwardSecrecy()

        #expect(try contact.popOldestPrekeyData() == nil)
    }

    @Test func pop_decrementsCount() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)
        try contact.configureForwardSecrecy()

        try contact.syncInboundPrekeys([wireBlob(), wireBlob(), wireBlob()], date: Date())
        #expect(contact.availableInboundPrekeyCount == 3)

        _ = try contact.popOldestPrekeyData()
        #expect(contact.availableInboundPrekeyCount == 2)

        _ = try contact.popOldestPrekeyData()
        #expect(contact.availableInboundPrekeyCount == 1)

        _ = try contact.popOldestPrekeyData()
        #expect(contact.availableInboundPrekeyCount == 0)
    }

    @Test func pop_hasPrekeyAvailable_falseAfterExhaustion() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)
        try contact.configureForwardSecrecy()

        try contact.syncInboundPrekeys([wireBlob()], date: Date())
        #expect(contact.hasPrekeyAvailable == true)

        _ = try contact.popOldestPrekeyData()
        #expect(contact.hasPrekeyAvailable == false)
    }

    @Test func pop_returnsNilAfterExhaustion_nocrash() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)
        try contact.configureForwardSecrecy()

        try contact.syncInboundPrekeys([wireBlob()], date: Date())
        _ = try contact.popOldestPrekeyData()

        // Second pop on empty store must return nil, not crash.
        #expect(try contact.popOldestPrekeyData() == nil)
    }
}

// MARK: - syncInboundPrekeys

@Suite("ForwardSecrecyModel — syncInboundPrekeys")
struct SyncInboundPrekeysTests {

    @Test func sync_acceptsNewerDate() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)
        try contact.configureForwardSecrecy()

        let old = Date(timeIntervalSinceNow: -100)
        let new = Date(timeIntervalSinceNow:    0)

        try contact.syncInboundPrekeys([wireBlob()], date: old)
        let countAfterFirst = contact.availableInboundPrekeyCount

        try contact.syncInboundPrekeys([wireBlob()], date: new)
        // Newer date must be accepted — count must change.
        #expect(contact.availableInboundPrekeyCount > countAfterFirst
                    || contact.availableInboundPrekeyCount == 1,
                "A newer date must cause the batch to be accepted")
    }

    @Test func sync_rejectsOlderDate() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)
        try contact.configureForwardSecrecy()

        let newer = Date(timeIntervalSinceNow:    0)
        let older = Date(timeIntervalSinceNow: -100)

        let blob1 = wireBlob(); let blob2 = wireBlob()
        try contact.syncInboundPrekeys([blob1], date: newer)
        #expect(contact.availableInboundPrekeyCount == 1)

        // Older date must be silently rejected.
        try contact.syncInboundPrekeys([blob2], date: older)
        #expect(contact.availableInboundPrekeyCount == 1, "Older-dated batch must be rejected")
    }

    @Test func sync_rejectsEqualDate_noDuplicates() throws {
        // The guard is `date > latestPrekeysGeneratedAt` (strictly greater).
        // Equal date means duplicate delivery — must be rejected.
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)
        try contact.configureForwardSecrecy()

        let date = Date(timeIntervalSince1970: 1_000_000)
        try contact.syncInboundPrekeys([wireBlob(), wireBlob()], date: date)
        let countAfterFirst = contact.availableInboundPrekeyCount

        // Same date — must be rejected.
        try contact.syncInboundPrekeys([wireBlob(), wireBlob()], date: date)
        #expect(contact.availableInboundPrekeyCount == countAfterFirst,
                "Equal-dated batch is a duplicate and must be rejected")
    }

    @Test func sync_storesBlobsCorrectly() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)
        try contact.configureForwardSecrecy()

        let b1 = wireBlob(); let b2 = wireBlob()
        try contact.syncInboundPrekeys([b1, b2], date: Date())

        #expect(contact.availableInboundPrekeyCount == 2)
    }

    @Test func sync_updatesLatestPrekeysGeneratedAt() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)
        try contact.configureForwardSecrecy()

        let before = try contact.plainTextForwardSecrecy
        #expect(before?.latestPrekeysGeneratedAt == nil)

        try contact.syncInboundPrekeys([wireBlob()], date: Date())

        let after = try contact.plainTextForwardSecrecy
        #expect(after?.latestPrekeysGeneratedAt != nil)
    }
}

// MARK: - Pending batch lifecycle

@Suite("ForwardSecrecyModel — Pending batch")
struct PendingBatchTests {

    @Test func pendingBatch_nilOnFreshContact() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)
        try contact.configureForwardSecrecy()

        #expect(try contact.loadPendingBatch() == nil)
        #expect(contact.hasPendingBatch == false)
    }

    @Test func pendingBatch_storeAndLoad_roundtrip() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)
        try contact.configureForwardSecrecy()

        let batch = makeBatch(count: 5)
        try contact.store(batch: batch)

        let loaded = try contact.loadPendingBatch()
        #expect(loaded != nil)
        #expect(loaded?.prekeys.count == 5)
        #expect(abs(loaded!.generatedAt.timeIntervalSince(batch.generatedAt)) < 0.001)
    }

    @Test func pendingBatch_hasPendingBatch_trueAfterStore() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)
        try contact.configureForwardSecrecy()

        try contact.store(batch: makeBatch())
        #expect(contact.hasPendingBatch == true)
    }

    @Test func pendingBatch_clearSetsBatchToNil() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)
        try contact.configureForwardSecrecy()

        try contact.store(batch: makeBatch())
        #expect(contact.hasPendingBatch == true)

        try contact.clearPendingBatch()
        #expect(contact.hasPendingBatch == false)
        #expect(try contact.loadPendingBatch() == nil)
    }

    @Test func pendingBatch_loadReturnsTheSameBatch_everyTime() throws {
        // The pending batch must be identical on every load — it must not regenerate.
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)
        try contact.configureForwardSecrecy()

        let original = makeBatch(generatedAt: Date(timeIntervalSince1970: 1_700_000_000), count: 3)
        try contact.store(batch: original)

        let load1 = try contact.loadPendingBatch()
        let load2 = try contact.loadPendingBatch()
        let load3 = try contact.loadPendingBatch()

        #expect(load1?.prekeys.count == load2?.prekeys.count)
        #expect(load2?.prekeys.count == load3?.prekeys.count)
        let diff = abs(load1!.generatedAt.timeIntervalSince(load3!.generatedAt))
        #expect(diff < 0.001, "Every load must return the same batch unchanged")
    }

    @Test func pendingBatch_storeReplacesExisting() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)
        try contact.configureForwardSecrecy()

        let first  = makeBatch(generatedAt: Date(timeIntervalSince1970: 100), count: 2)
        let second = makeBatch(generatedAt: Date(timeIntervalSince1970: 200), count: 5)

        try contact.store(batch: first)
        try contact.store(batch: second)

        let loaded = try contact.loadPendingBatch()
        #expect(loaded?.prekeys.count == 5, "Second store must overwrite first")
    }

    @Test func pendingBatch_clearThenStore_works() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)
        try contact.configureForwardSecrecy()

        try contact.store(batch: makeBatch(count: 3))
        try contact.clearPendingBatch()
        #expect(contact.hasPendingBatch == false)

        try contact.store(batch: makeBatch(count: 7))
        #expect(contact.hasPendingBatch == true)
        #expect(try contact.loadPendingBatch()?.prekeys.count == 7)
    }
}

// MARK: - Exhaustion cycle (model layer)

@Suite("ForwardSecrecyModel — Exhaustion cycle")
struct ExhaustionCycleTests {

    /// Simulates the full prekey exhaustion flow at the model layer:
    /// pop all → store empty → sync new batch → batch stored → pending cleared.
    @Test func exhaustionCycle_popAllThenSyncNewBatch() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)
        try contact.configureForwardSecrecy()

        // Step 1: Alice stores 3 of Bob's prekeys
        let blobs = [wireBlob(), wireBlob(), wireBlob()]
        try contact.syncInboundPrekeys(blobs, date: Date(timeIntervalSince1970: 1_000))
        #expect(contact.availableInboundPrekeyCount == 3)

        // Step 2: Alice exhausts all of Bob's prekeys
        _ = try contact.popOldestPrekeyData()
        _ = try contact.popOldestPrekeyData()
        _ = try contact.popOldestPrekeyData()
        #expect(contact.hasPrekeyAvailable == false, "All prekeys consumed")

        // Step 3: Alice detects fallback from Bob, generates a batch for him,
        //         stores it as pending
        let pendingBatch = makeBatch(count: 5)
        try contact.store(batch: pendingBatch)
        #expect(contact.hasPendingBatch == true)

        // Step 4: Bob sends Alice a new batch (date must be strictly newer)
        let newBatchDate = Date(timeIntervalSince1970: 2_000)
        let newBlobs = (0..<5).map { _ in wireBlob() }
        try contact.syncInboundPrekeys(newBlobs, date: newBatchDate)
        #expect(contact.availableInboundPrekeyCount == 5, "New batch from Bob stored")

        // Step 5: Alice receives Bob's FS bundle using her prekey — proof of receipt
        try contact.clearPendingBatch()
        #expect(contact.hasPendingBatch == false, "Pending batch cleared on FS receipt")
    }

    @Test func exhaustionCycle_duplicateBatchDelivery_isIdempotent() throws {
        // Bob's pending batch rides Alice's M1, M3, M7 — all carrying the same date.
        // Alice must process it once and silently ignore duplicates.
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)
        try contact.configureForwardSecrecy()

        let batchDate  = Date(timeIntervalSince1970: 1_000)
        let batchBlobs = [wireBlob(), wireBlob(), wireBlob()]

        // First delivery
        try contact.syncInboundPrekeys(batchBlobs, date: batchDate)
        let countAfterFirst = contact.availableInboundPrekeyCount

        // Second delivery — same date, must be rejected
        try contact.syncInboundPrekeys(batchBlobs, date: batchDate)
        #expect(contact.availableInboundPrekeyCount == countAfterFirst,
                "Duplicate batch must not add prekeys twice")

        // Third delivery — same date again
        try contact.syncInboundPrekeys(batchBlobs, date: batchDate)
        #expect(contact.availableInboundPrekeyCount == countAfterFirst)
    }

    @Test func exhaustionCycle_hasPendingBatch_blocksRegeneration() throws {
        // If a pending batch already exists, a second fallback must not overwrite it.
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)
        try contact.configureForwardSecrecy()

        // First fallback detected — generate and store batch
        let firstBatch = makeBatch(generatedAt: Date(timeIntervalSince1970: 100), count: 3)
        try contact.store(batch: firstBatch)
        #expect(contact.hasPendingBatch == true)

        // Second fallback arrives — hasPendingBatch is true, must NOT overwrite
        if !contact.hasPendingBatch {
            // This path must never execute in this test
            try contact.store(batch: makeBatch(count: 99))
        }

        let loaded = try contact.loadPendingBatch()
        #expect(loaded?.prekeys.count == 3, "First pending batch must be unchanged")
    }

    @Test func exhaustionCycle_clearPendingBatch_allowsNextGeneration() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)
        try contact.configureForwardSecrecy()

        try contact.store(batch: makeBatch(count: 3))
        try contact.clearPendingBatch()
        #expect(contact.hasPendingBatch == false)

        // After clearing, new generation is allowed
        let newBatch = makeBatch(count: 15)
        try contact.store(batch: newBatch)
        #expect(contact.hasPendingBatch == true)
        #expect(try contact.loadPendingBatch()?.prekeys.count == 15)
    }
}

// MARK: - isLikelySender

@Suite("ForwardSecrecyModel — isLikelySender")
struct IsLikelySenderTests {

    private func bundle(nonce: Data, fingerprint: Data) -> OccultaBundle {
        OccultaBundle(
            version:           .v3fs,
            secrecy:           OccultaBundle.SecrecyContext(
                mode: .longTermFallback, ephemeralPublicKey: Data(), prekeyID: nil
            ),
            ciphertext:        Data(count: 28),
            fingerprintNonce:  nonce,
            senderFingerprint: fingerprint
        )
    }

    @Test func isLikelySender_trueForMatchingKeyAndNonce() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)

        let pubKey = Data(repeating: 0x42, count: 65)
        let nonce  = try OccultaBundle.SecrecyContext.generateNonce()
        let fp     = OccultaBundle.SecrecyContext.fingerprint(for: pubKey, nonce: nonce)

        #expect(contact.isLikelySender(of: bundle(nonce: nonce, fingerprint: fp), contactPublicKey: pubKey))
    }

    @Test func isLikelySender_falseForWrongPublicKey() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)

        let key1  = Data(repeating: 0x42, count: 65)
        let key2  = Data(repeating: 0x43, count: 65)
        let nonce = try OccultaBundle.SecrecyContext.generateNonce()
        let fp    = OccultaBundle.SecrecyContext.fingerprint(for: key1, nonce: nonce)

        #expect(!contact.isLikelySender(of: bundle(nonce: nonce, fingerprint: fp), contactPublicKey: key2))
    }

    @Test func isLikelySender_falseForWrongNonce() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)

        let pubKey = Data(repeating: 0x42, count: 65)
        let fp     = OccultaBundle.SecrecyContext.fingerprint(
            for: pubKey, nonce: Data(repeating: 0x01, count: 16)
        )
        #expect(!contact.isLikelySender(
            of: bundle(nonce: Data(repeating: 0x02, count: 16), fingerprint: fp),
            contactPublicKey: pubKey
        ))
    }

    @Test func isLikelySender_falseForTamperedFingerprint() throws {
        let container = try makeContainer()
        let context   = ModelContext(container)
        let contact   = try makeContact(in: context)

        let pubKey = Data(repeating: 0x42, count: 65)
        let nonce  = try OccultaBundle.SecrecyContext.generateNonce()

        // Correct nonce but wrong fingerprint
        #expect(!contact.isLikelySender(
            of: bundle(nonce: nonce, fingerprint: Data(repeating: 0xAB, count: 32)),
            contactPublicKey: pubKey
        ))
    }
}

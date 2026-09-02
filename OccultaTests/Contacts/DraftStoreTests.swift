//
//  DraftStoreTests.swift
//  OccultaTests
//
//  Regression coverage for the stale-isSensitive race: scheduleSave used to capture
//  isSensitive as a Bool at schedule time and trust it 2 seconds later, unchanged,
//  when the actual write happened. Marking a contact sensitive mid-debounce (e.g. via
//  Trust Check) didn't cancel or invalidate the pending write, so a draft could be
//  written to disk moments after the purge meant to remove it — defeating save()'s
//  "Option E: no draft is ever written for a sensitive contact" guarantee.
//
//  The fix: isSensitive is a closure, called once, after the debounce delay,
//  immediately before the write — never captured early. These tests use a short
//  `debounceDelay` (DraftStore's test-only init parameter) instead of the real 2s,
//  so the suite runs fast.
//

import Testing
import Foundation
import SwiftData
@testable import Occulta

@MainActor
private func makeDraftContainer() throws -> ModelContainer {
    let schema = Schema([Message.Draft.self])
    return try ModelContainer(
        for: schema,
        configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)]
    )
}

/// Returns true if Manager.Key can derive the hybrid local key in this environment.
/// DraftStore always uses the real SE-backed key (never TestKeyManager) — these
/// tests skip gracefully wherever that's unavailable.
private func secureEnclaveAvailable() -> Bool {
    (try? Manager.Key().createHybridLocalEncryptionKey()) != nil
}

@MainActor
@Suite("DraftStore — stale isSensitive race")
struct DraftStoreRaceTests {

    /// The exact reported bug, reproduced: a keystroke schedules a save believing the
    /// contact is not sensitive; before the debounce fires, something (Trust Check, in
    /// production) marks it sensitive. The closure must observe that change and the
    /// draft must never be written.
    @Test func staleSensitivity_doesNotWriteWhenMarkedSensitiveDuringDebounce() async throws {
        guard secureEnclaveAvailable() else {
            print("⚠︎ Skipping — SE not available (simulator)")
            return
        }

        let container = try makeDraftContainer()
        let context   = ModelContext(container)
        let store     = DraftStore(debounceDelay: .milliseconds(200))

        // Mutable, closed-over "live" classification — mirrors ComposeViewModel.isSensitive
        // reading ContactManager's current state fresh on every call, not a snapshot.
        final class Box { var isSensitive = false }
        let liveClassification = Box()

        let recipientID = "contact-\(UUID().uuidString)"
        store.scheduleSave(
            recipientID:  recipientID,
            isSensitive:  { liveClassification.isSensitive },
            text:         "a message the user is typing",
            messages:     [],
            useThread:    false,
            modelContext: context
        )

        // Mid-debounce: the contact gets marked sensitive (Trust Check, in production).
        try await Task.sleep(for: .milliseconds(50))
        liveClassification.isSensitive = true

        // Generous fixed wait, well past the 200ms delay — confirming an absence, so
        // there's no positive condition to poll for; just give ample time for a write
        // to happen if it were going to.
        try await Task.sleep(for: .seconds(2))

        #expect(Message.Draft.find(recipientID: recipientID, in: context) == nil,
                """
                Draft was written even though the contact was marked sensitive before the \
                debounce fired — the closure must be evaluated fresh at write time, not \
                captured at schedule time.
                """)
    }

    /// Control case: if sensitivity never changes, the draft must still be written
    /// normally. Confirms the fix didn't just make scheduleSave a no-op.
    @Test func stillNotSensitive_writesNormallyAfterDebounce() async throws {
        guard secureEnclaveAvailable() else {
            print("⚠︎ Skipping — SE not available (simulator)")
            return
        }

        let container = try makeDraftContainer()
        let context   = ModelContext(container)
        let store     = DraftStore(debounceDelay: .milliseconds(200))

        let recipientID = "contact-\(UUID().uuidString)"
        store.scheduleSave(
            recipientID:  recipientID,
            isSensitive:  { false },
            text:         "a perfectly normal draft",
            messages:     [],
            useThread:    false,
            modelContext: context
        )

        await store.awaitPendingSave()

        #expect(Message.Draft.find(recipientID: recipientID, in: context) != nil,
                "a draft to a never-sensitive contact must still be written after the debounce")
    }

    /// A contact already sensitive from the very start (not just mid-debounce) must
    /// never get a draft written at all — the baseline "Option E" behavior, still
    /// correct after this change.
    @Test func alreadySensitiveFromTheStart_neverWrites() async throws {
        guard secureEnclaveAvailable() else {
            print("⚠︎ Skipping — SE not available (simulator)")
            return
        }

        let container = try makeDraftContainer()
        let context   = ModelContext(container)
        let store     = DraftStore(debounceDelay: .milliseconds(200))

        let recipientID = "contact-\(UUID().uuidString)"
        store.scheduleSave(
            recipientID:  recipientID,
            isSensitive:  { true },
            text:         "should never be written",
            messages:     [],
            useThread:    false,
            modelContext: context
        )

        try await Task.sleep(for: .seconds(2))

        #expect(Message.Draft.find(recipientID: recipientID, in: context) == nil,
                "a contact sensitive throughout the whole debounce window must never get a draft written")
    }

    /// A burst of keystrokes (each canceling the previous pending save) must only pay
    /// the isSensitive check once — for the final window that actually survives to
    /// completion — not once per keystroke. This is the performance half of the fix:
    /// isSensitive does a DB fetch + Secure Enclave decrypt, so evaluating it on every
    /// keystroke (as the old Bool-parameter design did) wastes SE round-trips on
    /// snapshots that get thrown away by the next keystroke's cancellation anyway.
    @Test func isSensitiveClosure_evaluatedOnlyOnce_acrossARapidKeystrokeBurst() async throws {
        guard secureEnclaveAvailable() else {
            print("⚠︎ Skipping — SE not available (simulator)")
            return
        }

        let container = try makeDraftContainer()
        let context   = ModelContext(container)
        let store     = DraftStore(debounceDelay: .milliseconds(200))

        final class CallCounter { var count = 0 }
        let counter = CallCounter()
        let recipientID = "contact-\(UUID().uuidString)"

        // Simulate 5 rapid keystrokes — each call cancels the previous pending Task.
        for _ in 0..<5 {
            store.scheduleSave(
                recipientID:  recipientID,
                isSensitive:  { counter.count += 1; return false },
                text:         "typing...",
                messages:     [],
                useThread:    false,
                modelContext: context
            )
            try await Task.sleep(for: .milliseconds(20))
        }

        await store.awaitPendingSave()

        #expect(counter.count == 1,
                "isSensitive should be evaluated exactly once for the one debounce window that survives, not once per keystroke — got \(counter.count) calls")
        #expect(Message.Draft.find(recipientID: recipientID, in: context) != nil,
                "the final keystroke's draft must still be written")
    }
}

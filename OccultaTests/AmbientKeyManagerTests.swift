//
//  AmbientKeyManagerTests.swift
//  OccultaTests
//
//  `Manager.Ambient` is the single source for keys every part of the app must agree on,
//  with a Debug-only task-local override so tests can run those paths on `TestKeyManager`.
//  These pin that the override is used, stays inside its task, never reaches a parallel
//  test, is honoured by `Manager.Crypto()`'s default key manager (the path most local-DB-key
//  reads take), and that a real `Manager.Key` built under it is counted — the leak check
//  `.ambientTestKeyManager` relies on.
//
//  None of these need a Secure Enclave, so they run on CI.
//

import Testing
import Foundation
@testable import Occulta

@MainActor
@Suite("Manager.Ambient — shared key manager seam")
struct AmbientKeyManagerTests {

    @Test func defaultsToTheRealKeyManager() {
        #expect(Manager.Ambient.keyManager is Manager.Key)
    }

    @Test func overrideIsUsedInsideItsScope() {
        let km = TestKeyManager()
        Manager.Ambient.$override.withValue(.init(km)) {
            #expect(Manager.Ambient.keyManager as AnyObject === km)
        }
    }

    @Test func overrideEndsWithItsScope() {
        Manager.Ambient.$override.withValue(.init(TestKeyManager())) { }
        #expect(Manager.Ambient.keyManager is Manager.Key)
    }

    /// `DraftStore` and others save from a `Task {}` — an unstructured task inherits
    /// task-locals, so those paths see the override too.
    @Test func unstructuredTaskInheritsTheOverride() async {
        let km = TestKeyManager()
        await Manager.Ambient.$override.withValue(.init(km)) {
            let seen = await Task { Manager.Ambient.keyManager as AnyObject }.value
            #expect(seen === km)
        }
    }

    /// Swift Testing runs tests in parallel in one process; each task must see only its own.
    @Test func concurrentOverridesDoNotCrossTalk() async {
        let first  = TestKeyManager()
        let second = TestKeyManager()
        await withTaskGroup(of: Bool.self) { group in
            for km in [first, second] {
                group.addTask { @MainActor in
                    await Manager.Ambient.$override.withValue(.init(km)) {
                        await Task.yield()
                        return Manager.Ambient.keyManager as AnyObject === km
                    }
                }
            }
            for await sawOwn in group { #expect(sawOwn) }
        }
    }

    /// `Manager.Crypto()` with no argument must take the ambient key manager, or a test
    /// that overrides it would seal under one key and open under another.
    @Test func defaultCryptoUsesTheOverride() throws {
        let km        = TestKeyManager()
        let plaintext = Data("ambient".utf8)

        let sealed = try Manager.Ambient.$override.withValue(.init(km)) {
            try Manager.Crypto().encrypt(data: plaintext)
        }

        #expect(try Manager.Crypto(keyManager: km).decrypt(data: sealed) == plaintext)
        #expect((try? Manager.Crypto(keyManager: TestKeyManager()).decrypt(data: sealed)) == nil)
    }

    // MARK: Leak detection

    @Test func realKeyBuiltUnderTheOverrideIsCounted() {
        let override = Manager.Ambient.Override(TestKeyManager())
        Manager.Ambient.$override.withValue(override) {
            _ = Manager.Key()
            _ = Manager.Key(testingTag: "ambient.leak.test")
        }
        #expect(override.realKeyConstructions == 2)
    }

    @Test func ambientReadsAreNotCounted() {
        let override = Manager.Ambient.Override(TestKeyManager())
        Manager.Ambient.$override.withValue(override) {
            _ = Manager.Ambient.keyManager
            _ = Manager.Crypto()
        }
        #expect(override.realKeyConstructions == 0)
    }

    @Test func realKeyBuiltWithNoOverrideIsNotCounted() {
        let override = Manager.Ambient.Override(TestKeyManager())
        Manager.Ambient.$override.withValue(override) { }
        _ = Manager.Key()
        #expect(override.realKeyConstructions == 0)
    }
}

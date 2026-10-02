//
//  AmbientTestKeyManagerTrait.swift
//  OccultaTests
//
//  `@Test(.ambientTestKeyManager)` runs a test with `Manager.Ambient` bound to a fresh
//  `TestKeyManager`, so code that derives the shared local DB key runs without a Secure
//  Enclave — on CI as well as here. Use it in place of `.enabled(if: secureEnclaveAvailable())`
//  wherever the local DB key was the only reason for the gate.
//
//  It also fails the test if a real `Manager.Key` was constructed while the override was
//  bound. That is a path the override doesn't reach: it would pass on this host only because
//  this host has an Enclave, and fail on CI.
//

import Testing
@testable import Occulta

struct AmbientTestKeyManagerTrait: TestTrait, SuiteTrait, TestScoping {
    /// On a suite, applies to each test inside it, so every test gets its own override
    /// and its own leak check rather than sharing one around the whole suite.
    var isRecursive: Bool { true }

    func provideScope(
        for test: Test,
        testCase: Test.Case?,
        performing function: @Sendable @concurrent () async throws -> Void
    ) async throws {
        let override = await MainActor.run { Manager.Ambient.Override(TestKeyManager()) }

        try await Manager.Ambient.$override.withValue(override) {
            try await function()
        }

        let leaks = await override.realKeyConstructions
        #expect(leaks == 0, "\(leaks) real Manager.Key constructed under the override — this path still needs a Secure Enclave")
    }
}

extension Trait where Self == AmbientTestKeyManagerTrait {
    static var ambientTestKeyManager: Self { Self() }
}

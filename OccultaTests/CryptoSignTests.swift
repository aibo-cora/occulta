//
//  CryptoSignTests.swift
//  OccultaTests
//
//  Regression coverage for SEC-3 / finding #9 (SecurityReview2026-07-24):
//  Manager.Crypto.sign(data:) used to return human-readable error strings
//  ("Key or data is missing", etc.) as its String return value, indistinguishable
//  from a real signature at any call site. It now throws instead.
//
//  Manager.Crypto.sign(data:) calls Manager.Key() directly (not an injected
//  KeyManagerProtocol), so its real Secure Enclave signing success path can't be
//  exercised here — same test-harness limitation documented elsewhere in this
//  codebase for other SE-backed operations. What's testable without hardware is
//  the type-level guarantee this fix exists for: failure throws, it never returns
//  a string that could be mistaken for a signature.
//

import Testing
@testable import Occulta

@Suite("Manager.Crypto.sign — throws instead of returning error strings")
struct CryptoSignTests {

    @Test func nilData_throwsRatherThanReturningAStringSignature() {
        let crypto = Manager.Crypto()
        #expect(throws: (any Error).self) {
            _ = try crypto.sign(data: nil)
        }
    }
}

//
//  SignedAttributeVerifyDateTests.swift
//  OccultaTests
//
//  Bug 176 — `SignedAttribute.verify(against:)` built the signing payload with
//  `UInt64(date.timeIntervalSince1970)`, which traps on a negative date and on one at or above 2^64. Both
//  dates come from the sender's JSON, which `JSONDecoder` reads as seconds since 2001 with no bounds, so a
//  shard operation could crash the receiver before the signature was looked at. `verify` now returns false for a
//  date the payload cannot encode.
//
//  A trap kills the test process rather than failing a test, so on the old code this suite shows up as a crashed
//  run, not a red case. No Secure Enclave: the key is a software P-256 key.
//

import Testing
import CryptoKit
import Foundation
@testable import Occulta
@testable import OccultaFormats

@MainActor
@Suite("SignedAttribute.verify — dates the signing payload cannot encode")
struct SignedAttributeVerifyDateTests {

    /// A shard attribute as a shard operation carries it: JSON, `Date` as seconds since 2001 (the default strategy).
    private func decode(createdAt: String, expiresAt: String = "null") throws -> SignedAttribute {
        let json = """
        {"id":"\(UUID().uuidString)","label":"x","value":"AAAA","category":"shard","signature":"AAAA","createdAt":\(createdAt),"expiresAt":\(expiresAt),"entryID":null}
        """
        return try JSONDecoder().decode(SignedAttribute.self, from: Data(json.utf8))
    }

    struct Case: Sendable, CustomTestStringConvertible {
        let createdAt: String
        let expiresAt: String
        var testDescription: String { "createdAt \(self.createdAt), expiresAt \(self.expiresAt)" }
    }

    @Test("A date the payload cannot encode makes verify return false instead of trapping", arguments: [
        Case(createdAt: "-1e12",                 expiresAt: "null"),
        Case(createdAt: "1e30",                  expiresAt: "null"),
        Case(createdAt: "1.0e9",                 expiresAt: "1e30"),
        // One second before 1970 (1970 is -978307200 seconds since 2001).
        Case(createdAt: "-978307201",            expiresAt: "null"),
        // 2^64 seconds since 2001, which is past 2^64 seconds since 1970.
        Case(createdAt: "1.8446744073709552e19", expiresAt: "null"),
    ])
    func unencodableDateIsRejected(_ testCase: Case) throws {
        let key       = P256.Signing.PrivateKey().publicKey.x963Representation
        let attribute = try self.decode(createdAt: testCase.createdAt, expiresAt: testCase.expiresAt)

        #expect(attribute.verify(against: key) == false)
    }

    @Test("Control: an encodable date with a bad signature is rejected by the signature check")
    func badSignatureIsRejected() throws {
        let key       = P256.Signing.PrivateKey().publicKey.x963Representation
        let attribute = try self.decode(createdAt: "1.0e9")

        #expect(attribute.verify(against: key) == false)
    }

    @Test("Control: an encodable date with a real signature verifies, so the guard does not over-reject")
    func realSignatureVerifies() throws {
        let signer    = P256.Signing.PrivateKey()
        let id        = UUID()
        let value     = Data([1, 2, 3, 4])
        let createdAt = Date(timeIntervalSinceReferenceDate: 1.0e9)
        let expiresAt = Date(timeIntervalSinceNow: 3600)
        let payload   = SignedAttribute.signingPayload(
            id: id, category: .shard, value: value, entryID: nil, createdAt: createdAt, expiresAt: expiresAt
        )
        let signed = SignedAttribute(
            id: id, label: "x", value: value, category: .shard,
            signature: try signer.signature(for: payload).derRepresentation,
            createdAt: createdAt, expiresAt: expiresAt, entryID: nil
        )
        // Through the wire form, so the dates are the ones a receiver decodes.
        let received = try JSONDecoder().decode(SignedAttribute.self, from: try JSONEncoder().encode(signed))

        #expect(received.verify(against: signer.publicKey.x963Representation))
    }
}

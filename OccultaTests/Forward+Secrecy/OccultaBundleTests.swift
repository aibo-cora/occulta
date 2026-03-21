//
//  OccultaBundleTests.swift
//  OccultaTests
//
//  Tests for OccultaBundle structure, serialisation, and fingerprint math.
//  No SE. No Manager.Crypto. No SwiftData.
//  These tests are safe to run in the simulator.
//

import XCTest
internal import CryptoKit
@testable import Occulta

final class OccultaBundleTests: XCTestCase {

    // MARK: - Helpers

    private func makeBundle(
        mode:          OccultaBundle.Mode = .forwardSecret,
        prekeyID:      String?            = "test-prekey-id",
        prekeySeq:     Int?               = 3,
        nonce:         Data               = Data(repeating: 0x01, count: 16),
        fingerprint:   Data               = Data(repeating: 0xAB, count: 32),
        ciphertext:    Data               = Data(repeating: 0xFF, count: 64),
        prekeyBatch:   OccultaBundle.PrekeySyncBatch? = nil
    ) -> OccultaBundle {
        let secrecy = OccultaBundle.SecrecyContext(
            mode:               mode,
            ephemeralPublicKey: Data(count: 65),
            prekeyID:           prekeyID,
            prekeySequence:     prekeySeq,
            prekeyBatch:        prekeyBatch
        )
        
        return OccultaBundle(version: OccultaBundle.currentVersion, secrecy: secrecy, ciphertext: ciphertext, fingerprintNonce: nonce, senderFingerprint: fingerprint)
    }

    // MARK: - Version

    func test_currentVersion_isV3fs() {
        XCTAssertEqual(OccultaBundle.currentVersion, .v3fs)
    }

    func test_versionRawValues() {
        XCTAssertEqual(OccultaBundle.Version.v1.rawValue,   "v1")
        XCTAssertEqual(OccultaBundle.Version.v2.rawValue,   "v2")
        XCTAssertEqual(OccultaBundle.Version.v3fs.rawValue, "v3fs")
    }

    // MARK: - Mode

    func test_modeRawValues() {
        XCTAssertEqual(OccultaBundle.Mode.forwardSecret.rawValue,   "forwardSecret")
        XCTAssertEqual(OccultaBundle.Mode.longTermFallback.rawValue, "longTermFallback")
    }

    // MARK: - UI helpers

    func test_isForwardSecret_trueForFSMode() {
        let bundle = makeBundle(mode: .forwardSecret)
        XCTAssertTrue(bundle.isForwardSecret)
    }

    func test_isForwardSecret_falseForFallbackMode() {
        let bundle = makeBundle(mode: .longTermFallback)
        XCTAssertFalse(bundle.isForwardSecret)
    }

    func test_securityLabel_forwardSecret() {
        XCTAssertEqual(makeBundle(mode: .forwardSecret).securityLabel,   "Forward Secret")
    }

    func test_securityLabel_fallback() {
        XCTAssertEqual(makeBundle(mode: .longTermFallback).securityLabel, "Standard Encryption")
    }

    // MARK: - Serialisation roundtrip

    func test_encodeDecode_preservesVersion() throws {
        let original = makeBundle()
        let decoded  = try OccultaBundle.decode(from: original.encode())
        
        XCTAssertEqual(decoded.version, original.version)
    }

    func test_encodeDecode_preservesMode() throws {
        for mode in [OccultaBundle.Mode.forwardSecret, .longTermFallback] {
            let original = makeBundle(mode: mode)
            let decoded  = try OccultaBundle.decode(from: original.encode())
            
            XCTAssertEqual(decoded.secrecy.mode, original.secrecy.mode)
        }
    }

    func test_encodeDecode_preservesPrekeyIDAndSequence() throws {
        let original = makeBundle(prekeyID: "xyz", prekeySeq: 7)
        let decoded  = try OccultaBundle.decode(from: original.encode())
        
        XCTAssertEqual(decoded.secrecy.prekeyID,       "xyz")
        XCTAssertEqual(decoded.secrecy.prekeySequence, 7)
    }

    func test_encodeDecode_nilPrekeyIDOnFallback() throws {
        let original = makeBundle(mode: .longTermFallback, prekeyID: nil, prekeySeq: nil)
        let decoded  = try OccultaBundle.decode(from: original.encode())
        
        XCTAssertNil(decoded.secrecy.prekeyID)
        XCTAssertNil(decoded.secrecy.prekeySequence)
    }

    func test_encodeDecode_preservesFingerprintFields() throws {
        let nonce       = Data((0..<16).map { UInt8($0) })
        let fingerprint = Data((0..<32).map { UInt8($0 &+ 100) })
        let original    = makeBundle(nonce: nonce, fingerprint: fingerprint)
        let decoded     = try OccultaBundle.decode(from: original.encode())
        
        XCTAssertEqual(decoded.fingerprintNonce,  nonce)
        XCTAssertEqual(decoded.senderFingerprint, fingerprint)
    }

    func test_encodeDecode_preservesCiphertext() throws {
        let ciphertext = Data((0..<128).map { UInt8($0) })
        let original   = makeBundle(ciphertext: ciphertext)
        let decoded    = try OccultaBundle.decode(from: original.encode())
        
        XCTAssertEqual(decoded.ciphertext, original.ciphertext)
    }

    func test_encodeDecode_preservesPrekeyBatch() throws {
        let prekeys = [
            Prekey(id: "A", contactID: "c", sequence: 1, publicKey: Data(count: 65)),
            Prekey(id: "B", contactID: "c", sequence: 1, publicKey: Data(count: 65))
        ]
        let batch    = OccultaBundle.PrekeySyncBatch(sequence: 1, prekeys: prekeys)
        let original = makeBundle(prekeyBatch: batch)
        let decoded  = try OccultaBundle.decode(from: original.encode())

        XCTAssertEqual(decoded.secrecy.prekeyBatch?.sequence, 1)
        XCTAssertEqual(decoded.secrecy.prekeyBatch?.prekeys.count, 2)
        XCTAssertEqual(decoded.secrecy.prekeyBatch?.prekeys[0].id, "A")
        XCTAssertEqual(decoded.secrecy.prekeyBatch?.prekeys[1].id, "B")
    }

    func test_decodeMalformedData_throws() {
        XCTAssertThrowsError(
            try OccultaBundle.decode(from: Data("not json".utf8))
        )
    }

    // MARK: - Fingerprint math

    func test_fingerprint_isSHA256OfPublicKeyPlusNonce() {
        let publicKey = Data(repeating: 0x42, count: 65)
        let nonce     = Data(repeating: 0x11, count: 16)
        
        var input     = publicKey
        input.append(nonce)

        let expected = Data(SHA256.hash(data: input))
        let actual   = OccultaBundle.SecrecyContext.fingerprint(for: publicKey, nonce: nonce)

        XCTAssertEqual(actual, expected)
    }

    func test_fingerprint_differentNonce_producesDifferentResult() {
        let publicKey = Data(repeating: 0x42, count: 65)
        let nonce1    = Data(repeating: 0x01, count: 16)
        let nonce2    = Data(repeating: 0x02, count: 16)

        let fp1 = OccultaBundle.SecrecyContext.fingerprint(for: publicKey, nonce: nonce1)
        let fp2 = OccultaBundle.SecrecyContext.fingerprint(for: publicKey, nonce: nonce2)

        XCTAssertNotEqual(fp1, fp2, "Different nonces must produce different fingerprints for the same key")
    }

    func test_fingerprint_differentKey_producesDifferentResult() {
        let key1  = Data(repeating: 0x01, count: 65)
        let key2  = Data(repeating: 0x02, count: 65)
        let nonce = Data(repeating: 0x99, count: 16)

        let fp1 = OccultaBundle.SecrecyContext.fingerprint(for: key1, nonce: nonce)
        let fp2 = OccultaBundle.SecrecyContext.fingerprint(for: key2, nonce: nonce)

        XCTAssertNotEqual(fp1, fp2)
    }

    func test_fingerprint_is32Bytes() {
        let result = OccultaBundle.SecrecyContext.fingerprint(for: Data(count: 65), nonce: Data(count: 16)
        )
        XCTAssertEqual(result.count, 32)
    }

    func test_generateNonce_is16Bytes() {
        let nonce = OccultaBundle.SecrecyContext.generateNonce()
        
        XCTAssertEqual(nonce.count, 16)
    }

    func test_generateNonce_isRandomEachCall() {
        let n1 = OccultaBundle.SecrecyContext.generateNonce()
        let n2 = OccultaBundle.SecrecyContext.generateNonce()
        
        XCTAssertNotEqual(n1, n2, "Consecutive nonces must not be equal (astronomically unlikely if truly random)")
    }

    // MARK: - PrekeySyncBatch

    func test_prekeySyncBatch_encodeDecode() throws {
        let prekeys = [Prekey(id: "X", contactID: "c", sequence: 5, publicKey: Data(count: 65))]
        let batch   = OccultaBundle.PrekeySyncBatch(sequence: 5, prekeys: prekeys)
        let data    = try JSONEncoder().encode(batch)
        let decoded = try JSONDecoder().decode(OccultaBundle.PrekeySyncBatch.self, from: data)

        XCTAssertEqual(decoded.sequence,         5)
        XCTAssertEqual(decoded.prekeys.count,    1)
        XCTAssertEqual(decoded.prekeys[0].id,    "X")
        XCTAssertEqual(decoded.prekeys[0].sequence, 5)
    }
}
